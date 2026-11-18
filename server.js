require("dotenv").config();

const express = require("express");
const http = require("http");
const path = require("path");
const crypto = require("crypto");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const MongoStore = require("connect-mongo").default;
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server, { maxHttpBufferSize: 2_000_000 });

const PORT = process.env.PORT || 3000;
const MESSAGE_LIFETIME = 5 * 60 * 1000;
const MAX_AUDIO_BYTES = 1_000_000;
const MAX_MESSAGES_PER_ROOM = 100;

const rooms = new Map();
const expiryTimers = new Map();
const activeCalls = new Map();

app.disable("x-powered-by");
app.use(express.json({ limit: "20kb" }));
app.use(express.urlencoded({ extended: false }));

// ---------------- USER MODEL ----------------
const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 30 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true, maxlength: 254 },
  passwordHash: { type: String, required: true, select: false }
}, { timestamps: true });
const User = mongoose.model("User", userSchema);

// ---------------- PRIVATE ROOM MODEL ----------------
const privateRoomSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 50 },
  code: { type: String, required: true, unique: true, index: true },
  ownerId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  memberIds: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  invitations: [{
    email: { type: String, required: true, lowercase: true, trim: true },
    tokenHash: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
    acceptedAt: { type: Date, default: null }
  }]
}, { timestamps: true });
const PrivateRoom = mongoose.model("PrivateRoom", privateRoomSchema);

// ---------------- ROOM REQUEST MODEL ----------------
const roomRequestSchema = new mongoose.Schema({
  roomId: { type: mongoose.Schema.Types.ObjectId, ref: "PrivateRoom", required: true, index: true },
  roomCode: { type: String, required: true },
  roomName: { type: String, required: true },
  senderId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  recipientId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
  status: { type: String, enum: ["pending", "accepted", "rejected"], default: "pending", index: true }
}, { timestamps: true });
roomRequestSchema.index({ roomId: 1, recipientId: 1, status: 1 });
const RoomRequest = mongoose.model("RoomRequest", roomRequestSchema);

// ---------------- MESSAGE MODEL ----------------
const messageSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  room: { type: String, required: true, index: true },
  name: { type: String, required: true },
  senderId: { type: String, required: true },
  senderUserId: { type: String, required: true },
  text: { type: String, default: "" },
  audio: { type: Buffer },
  mimeType: { type: String },
  type: { type: String, enum: ["text", "audio"], required: true },
  createdAt: { type: Number, required: true },
  seenAt: { type: Number, default: null },
  expiresAt: { type: Date, default: undefined }
});
messageSchema.index({ room: 1, createdAt: -1 });
messageSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
const Message = mongoose.model("Message", messageSchema);
// ---------------- SESSIONS ----------------

if (!process.env.SESSION_SECRET) {
  throw new Error("SESSION_SECRET is missing from your .env file.");
}

if (!process.env.MONGODB_URI) {
  throw new Error("MONGODB_URI is missing from your .env file.");
}

// Trust Render's reverse proxy for HTTPS cookies
app.set("trust proxy", 1);

const sessionMiddleware = session({
  name: "fiveMChat.sid",
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,

  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    collectionName: "sessions",
    ttl: 7 * 24 * 60 * 60
  }),

  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
});

app.use(sessionMiddleware);
io.engine.use(sessionMiddleware);
// ---------------- HELPERS ----------------
function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) {
    if (req.path.startsWith("/api/")) {
      return res.status(401).json({ success: false, message: "Please log in." });
    }cookie:
    return res.redirect("/login.html");
  }
  next();
}
function cleanRoom(value) {
  return String(value || "").trim().replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 40);
}
function cleanName(value) {
  return String(value || "Guest").trim().replace(/\s+/g, " ").slice(0, 30) || "Guest";
}
function validEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}
function publicUser(user) {
  return { id: String(user._id), name: user.name, email: user.email };
}
function regenerateSession(req) {
  return new Promise((resolve, reject) => req.session.regenerate(error => error ? reject(error) : resolve()));
}
function saveSession(req) {
  return new Promise((resolve, reject) => req.session.save(error => error ? reject(error) : resolve()));
}
async function startLoginSession(req, user) {
  await regenerateSession(req);
  req.session.userId = String(user._id);
  req.session.name = user.name;
  req.session.email = user.email;
  await saveSession(req);
}
function makeMessageId() {
  return `${Date.now()}-${crypto.randomUUID()}`;
}
function toMessagePayload(doc) {
  const message = doc.toObject ? doc.toObject() : doc;
  return {
    id: message.id, room: message.room, name: message.name,
    senderId: message.senderId, senderUserId: message.senderUserId,
    text: message.text || "",
    ...(message.audio ? { audio: message.audio } : {}),
    ...(message.mimeType ? { mimeType: message.mimeType } : {}),
    type: message.type, createdAt: message.createdAt, seenAt: message.seenAt || null
  };
}
function getRoomMessages(room) {
  if (!rooms.has(room)) rooms.set(room, []);
  return rooms.get(room);
}
function broadcastSystem(room, text) {
  io.to(room).emit("system-message", { text, createdAt: Date.now() });
}
function broadcastOnlineUsers(room) {
  const socketIds = io.sockets.adapter.rooms.get(room);
  const users = [];

  if (socketIds) {
    for (const id of socketIds) {
      const connectedSocket = io.sockets.sockets.get(id);

      if (
        connectedSocket &&
        connectedSocket.data.room === room &&
        connectedSocket.data.roomAuthorized
      ) {
        users.push({
          id,
          socketId: id,
          userId: connectedSocket.data.userId,
          name: connectedSocket.data.name || "User"
        });
      }
    }
  }

  io.to(room).emit("online-users", users);
}
async function userIsRoomMember(roomCode, userId) {
  if (!roomCode || !userId) return false;
  const room = await PrivateRoom.findOne({ code: roomCode, memberIds: userId }).select("_id").lean();
  return Boolean(room);
}

// ---------------- MESSAGE EXPIRY ----------------
async function removeMessage(room, messageId) {
  const key = `${room}:${messageId}`;
  const timer = expiryTimers.get(key);
  if (timer) clearTimeout(timer);
  expiryTimers.delete(key);
  try {
    await Message.deleteOne({ room, id: messageId });
    const messages = getRoomMessages(room);
    const index = messages.findIndex(message => message.id === messageId);
    if (index !== -1) messages.splice(index, 1);
    io.to(room).emit("message-expired", { messageId });
  } catch (error) {
    console.error("Message deletion error:", error.message);
  }
}
function scheduleExpiry(room, messageId, expiresAt) {
  const key = `${room}:${messageId}`;
  if (expiryTimers.has(key)) return;
  const remaining = Math.max(0, expiresAt - Date.now());
  const timer = setTimeout(() => { removeMessage(room, messageId); }, remaining);
  expiryTimers.set(key, timer);
}
async function loadRoomMessages(room) {
  const now = new Date();
  const documents = await Message.find({
    room,
    $or: [
      { expiresAt: { $exists: false } },
      { expiresAt: null },
      { expiresAt: { $gt: now } }
    ]
  }).sort({ createdAt: 1 }).lean();
  const messages = documents.map(toMessagePayload);
  rooms.set(room, messages);
  for (const document of documents) {
    if (document.expiresAt) scheduleExpiry(room, document.id, document.expiresAt.getTime());
  }
  return messages;
}
async function addMessage(room, message) {
  try {
    const saved = await Message.create(message);
    const payload = toMessagePayload(saved);
    const messages = getRoomMessages(room);
    messages.push(payload);
    while (messages.length > MAX_MESSAGES_PER_ROOM) {
      const removed = messages.shift();
      const key = `${room}:${removed.id}`;
      const timer = expiryTimers.get(key);
      if (timer) clearTimeout(timer);
      expiryTimers.delete(key);
      await Message.deleteOne({ room, id: removed.id });
    }
    io.to(room).emit("new-message", payload);
  } catch (error) {
    console.error("Message save error:", error.message);
  }
}

// ---------------- AUTH API ----------------
app.post("/api/auth/register", async (req, res) => {
  try {
    const name = cleanName(req.body.name);
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    if (!name || name === "Guest" || name.length < 2 || !validEmail(email) || email.length > 254 || password.length < 8 || Buffer.byteLength(password, "utf8") > 72) {
      return res.status(400).json({ success: false, message: "Enter a name of 2–30 characters, a valid email, and a password of 8–72 bytes." });
    }
    const existing = await User.findOne({ email }).lean();
    if (existing) return res.status(409).json({ success: false, message: "An account with this email already exists." });
    const user = await User.create({ name, email, passwordHash: await bcrypt.hash(password, 12) });
    await startLoginSession(req, user);
    res.status(201).json({ success: true, user: publicUser(user) });
  } catch (error) {
    if (error.code === 11000) return res.status(409).json({ success: false, message: "An account with this email already exists." });
    console.error("Registration error:", error.message);
    res.status(500).json({ success: false, message: "Could not create your account. Please try again." });
  }
});
app.post("/api/auth/login", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    if (!validEmail(email) || email.length > 254 || !password || Buffer.byteLength(password, "utf8") > 72) {
      return res.status(400).json({ success: false, message: "Enter a valid email and password." });
    }
    const user = await User.findOne({ email }).select("+passwordHash");
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) return res.status(401).json({ success: false, message: "Incorrect email or password." });
    await startLoginSession(req, user);
    res.json({ success: true, user: publicUser(user) });
  } catch (error) {
    console.error("Login error:", error.message);
    res.status(500).json({ success: false, message: "Could not log in. Please try again." });
  }
});
app.get("/api/auth/me", async (req, res) => {
  try {
    if (!req.session.userId) return res.status(401).json({ success: false, message: "Please log in." });
    const user = await User.findById(req.session.userId);
    if (!user) return req.session.destroy(() => res.status(401).json({ success: false, message: "Please log in again." }));
    res.json({ success: true, user: publicUser(user) });
  } catch (error) {
    res.status(500).json({ success: false, message: "Could not check your account." });
  }
});
app.post("/api/auth/logout", (req, res) => {
  if (!req.session) return res.json({ success: true });
  req.session.destroy(error => {
    if (error) return res.status(500).json({ success: false, message: "Could not log out." });
    res.clearCookie("fiveMChat.sid", { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production" });
    res.json({ success: true });
  });
});

// ---------------- PRIVATE ROOM API ----------------
// Create a room. Its creator is the first member and owner.
app.post("/api/rooms", requireAuth, async (req, res) => {
  try {
    const roomName = String(req.body.name || "").trim();
    if (!roomName || roomName.length > 50) return res.status(400).json({ success: false, message: "Room name must be between 1 and 50 characters." });
    let roomCode;
    let exists;
    do {
      roomCode = crypto.randomBytes(4).toString("hex").toUpperCase();
      exists = await PrivateRoom.findOne({ code: roomCode }).select("_id").lean();
    } while (exists);
    const newRoom = await PrivateRoom.create({ name: roomName, code: roomCode, ownerId: req.session.userId, memberIds: [req.session.userId], invitations: [] });
    res.status(201).json({ success: true, message: "Private room created successfully.", room: { id: String(newRoom._id), name: newRoom.name, code: newRoom.code, owner: true } });
  } catch (error) {
    console.error("Create room error:", error.message);
    res.status(500).json({ success: false, message: "Could not create the private room." });
  }
});

// Join a room using its shareable room code. A valid code grants membership.
app.post("/api/rooms/join", requireAuth, async (req, res) => {
  try {
    const code = cleanRoom(req.body.code).toUpperCase();
    if (!code) return res.status(400).json({ success: false, message: "Enter a valid room code." });

    const room = await PrivateRoom.findOne({ code });
    if (!room) return res.status(404).json({ success: false, message: "Room code not found. Check the code and try again." });

    const userObjectId = new mongoose.Types.ObjectId(req.session.userId);
    const updatedRoom = await PrivateRoom.findOneAndUpdate(
      { _id: room._id },
      { $addToSet: { memberIds: userObjectId } },
      { new: true }
    ).select("_id name code memberIds");

    if (!updatedRoom || !updatedRoom.memberIds.some(id => String(id) === String(userObjectId))) {
      return res.status(500).json({ success: false, message: "Could not save your room membership. Please try again." });
    }

    return res.json({
      success: true,
      message: "You joined \"" + room.name + "\" successfully.",
      room: { id: String(room._id), name: room.name, code: room.code }
    });
  } catch (error) {
    console.error("Join room by code error:", error.message);
    return res.status(500).json({ success: false, message: "Could not join this room. Please try again." });
  }
});

// List rooms the logged-in user belongs to.
app.get("/api/rooms", requireAuth, async (req, res) => {
  try {
    const list = await PrivateRoom.find({ memberIds: req.session.userId }).sort({ updatedAt: -1 }).lean();
    res.json({ success: true, rooms: list.map(room => ({ id: String(room._id), name: room.name, code: room.code, owner: String(room.ownerId) === String(req.session.userId) })) });
  } catch (error) {
    console.error("List rooms error:", error.message);
    res.status(500).json({ success: false, message: "Could not load your rooms." });
  }
});

// ---------------- DELETE PRIVATE ROOM ----------------
app.delete("/api/rooms/:id", requireAuth, async (req, res) => {
  try {
    const room = await PrivateRoom.findById(req.params.id);

    if (!room) {
      return res.status(404).json({
        success: false,
        message: "Room not found."
      });
    }

    if (String(room.ownerId) !== String(req.session.userId)) {
      return res.status(403).json({
        success: false,
        message: "Only the room owner can delete this room."
      });
    }

    await Message.deleteMany({ roomId: room._id });
    await RoomRequest.deleteMany({ roomId: room._id });
    await PrivateRoom.deleteOne({ _id: room._id });

    return res.json({
      success: true,
      message: "Room deleted successfully."
    });

  } catch (error) {
    console.error("Delete room error:", error.message);

    return res.status(500).json({
      success: false,
      message: "Could not delete the room."
    });
  }
});

// Send a room request to a registered user by email.
app.post("/api/rooms/:code/request", requireAuth, async (req, res) => {
  try {
    const code = cleanRoom(req.params.code).toUpperCase();
    const email = String(req.body.email || "").trim().toLowerCase();
    if (!validEmail(email) || email.length > 254) {
      return res.status(400).json({ success: false, message: "Enter a valid email address." });
    }

    const room = await PrivateRoom.findOne({ code });
    if (!room) return res.status(404).json({ success: false, message: "Room not found." });
    if (String(room.ownerId) !== String(req.session.userId)) {
      return res.status(403).json({ success: false, message: "Only the room owner can send room requests." });
    }

    const recipient = await User.findOne({ email }).select("_id name email");
    if (!recipient) return res.status(404).json({ success: false, message: "That email is not registered on 5M Chat." });
    if (String(recipient._id) === String(req.session.userId)) {
      return res.status(400).json({ success: false, message: "You cannot send a request to yourself." });
    }
    if (room.memberIds.some(id => String(id) === String(recipient._id))) {
      return res.status(409).json({ success: false, message: "This user is already a room member." });
    }

    const existing = await RoomRequest.findOne({ roomId: room._id, recipientId: recipient._id, status: "pending" });
    if (existing) return res.status(409).json({ success: false, message: "A request is already waiting for this user." });

    const request = await RoomRequest.create({
      roomId: room._id, roomCode: room.code, roomName: room.name,
      senderId: req.session.userId, recipientId: recipient._id, status: "pending"
    });
    io.to(`user:${String(recipient._id)}`).emit("room-request", {
      id: String(request._id), roomCode: room.code, roomName: room.name, senderName: req.session.name || "Someone"
    });
    return res.status(201).json({ success: true, message: "Room request sent successfully." });
  } catch (error) {
    console.error("Send room request error:", error.message);
    return res.status(500).json({ success: false, message: "Could not send the room request." });
  }
});

// List pending room requests for the signed-in recipient.
app.get("/api/requests", requireAuth, async (req, res) => {
  try {
    const requests = await RoomRequest.find({ recipientId: req.session.userId, status: "pending" }).sort({ createdAt: -1 }).lean();
    const result = await Promise.all(requests.map(async request => {
      const sender = await User.findById(request.senderId).select("name email").lean();
      return { id: String(request._id), roomId: String(request.roomId), roomCode: request.roomCode, roomName: request.roomName, senderName: sender?.name || "Someone", senderEmail: sender?.email || "" };
    }));
    return res.json({ success: true, requests: result });
  } catch (error) {
    console.error("Load room requests error:", error.message);
    return res.status(500).json({ success: false, message: "Could not load room requests." });
  }
});

// Accept or reject a pending request. Accepting adds the recipient to the room.
async function respondToRoomRequest(req, res, action) {
  try {
    const request = await RoomRequest.findOne({ _id: req.params.id, recipientId: req.session.userId, status: "pending" });
    if (!request) return res.status(404).json({ success: false, message: "This room request is no longer available." });
    if (action === "accept") {
      const room = await PrivateRoom.findById(request.roomId);
      if (!room) {
        request.status = "rejected";
        await request.save();
        return res.status(404).json({ success: false, message: "This room no longer exists." });
      }
      if (!room.memberIds.some(id => String(id) === String(req.session.userId))) {
        room.memberIds.push(req.session.userId);
        await room.save();
      }
      request.status = "accepted";
      await request.save();
      return res.json({ success: true, message: "Request accepted. You have joined the room." });
    }
    request.status = "rejected";
    await request.save();
    return res.json({ success: true, message: "Room request rejected." });
  } catch (error) {
    console.error(`Room request ${action} error:`, error.message);
    return res.status(500).json({ success: false, message: "Could not process this room request." });
  }
}
app.post("/api/requests/:id/accept", requireAuth, (req, res) => respondToRoomRequest(req, res, "accept"));
app.post("/api/requests/:id/reject", requireAuth, (req, res) => respondToRoomRequest(req, res, "reject"));

// Owner invites an already-registered user. The token is shown once to the owner.
app.post("/api/rooms/:code/invite", requireAuth, async (req, res) => {
  try {
    const code = cleanRoom(req.params.code);
    const email = String(req.body.email || "").trim().toLowerCase();
    if (!validEmail(email) || email.length > 254) return res.status(400).json({ success: false, message: "Please enter a valid email address." });
    const room = await PrivateRoom.findOne({ code });
    if (!room) return res.status(404).json({ success: false, message: "Private room not found." });
    if (String(room.ownerId) !== String(req.session.userId)) return res.status(403).json({ success: false, message: "Only the room owner can invite users." });
    const invitedUser = await User.findOne({ email }).select("_id email");
    if (!invitedUser) return res.status(404).json({ success: false, message: "That email is not registered on 5M Chat yet." });
    if (room.memberIds.some(id => String(id) === String(invitedUser._id))) return res.status(409).json({ success: false, message: "This user is already a room member." });
    const token = crypto.randomBytes(32).toString("hex");
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    room.invitations = room.invitations.filter(invitation => invitation.email !== email);
    room.invitations.push({ email, tokenHash, createdAt: new Date(), acceptedAt: null });
    await room.save();
    res.json({ success: true, message: "Invitation created. Share this token privately with the invited user.", invitationToken: token, roomName: room.name, roomCode: room.code, invitedEmail: email });
  } catch (error) {
    console.error("Invite user error:", error.message);
    res.status(500).json({ success: false, message: "Could not invite this user." });
  }
});

// Invited user accepts with the token, while logged in to the invited email account.
app.post("/api/rooms/:code/accept", requireAuth, async (req, res) => {
  try {
    const code = cleanRoom(req.params.code);
    const token = String(req.body.token || "").trim();
    if (!token || token.length > 200) return res.status(400).json({ success: false, message: "Enter a valid invitation token." });
    const user = await User.findById(req.session.userId).select("email");
    if (!user) return res.status(401).json({ success: false, message: "Please log in again." });
    const room = await PrivateRoom.findOne({ code });
    if (!room) return res.status(404).json({ success: false, message: "Private room not found." });
    if (room.memberIds.some(id => String(id) === String(user._id))) return res.json({ success: true, message: "You are already a room member.", room: { name: room.name, code: room.code } });
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    const invitation = room.invitations.find(item => item.email === user.email && item.tokenHash === tokenHash && !item.acceptedAt);
    if (!invitation) return res.status(403).json({ success: false, message: "This invitation is invalid, already used, or belongs to another email account." });
    invitation.acceptedAt = new Date();
    room.memberIds.push(user._id);
    await room.save();
    res.json({ success: true, message: "Invitation accepted. You can now join the private room.", room: { name: room.name, code: room.code } });
  } catch (error) {
    console.error("Accept invitation error:", error.message);
    res.status(500).json({ success: false, message: "Could not accept the invitation." });
  }
});

// ---------------- PAGE ROUTES ----------------
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("/login.html", (req, res) => res.sendFile(path.join(__dirname, "public", "login.html")));
app.get("/chat.html", requireAuth, (req, res) => res.sendFile(path.join(__dirname, "public", "chat.html")));
app.get("/api/status", (req, res) => {
  res.json({ success: true, message: "5M Chat backend is working!", database: mongoose.connection.readyState === 1 ? "connected" : "disconnected" });
});
app.use(express.static(path.join(__dirname, "public")));

// ---------------- AUTHENTICATED SOCKETS ----------------

io.use((socket, next) => {
  const sessionData = socket.request.session;

  if (!sessionData || !sessionData.userId) {
    return next(new Error("Please log in to use 5M Chat."));
  }

  socket.data.userId = String(sessionData.userId);
  socket.data.name = cleanName(sessionData.name);
  socket.join(`user:${socket.data.userId}`);

  next();
});

io.on("connection", socket => {
  socket.data.room = null;
  socket.data.roomAuthorized = false;
  socket.data.seenMessages = new Set();

  // ---------------- JOIN CHAT ----------------

  socket.on("join-chat", async ({ room } = {}) => {
    try {
      const safeRoom = cleanRoom(room);

      if (!safeRoom) {
        return socket.emit("join-error", "Enter a valid room code.");
      }

      const userObjectId = new mongoose.Types.ObjectId(socket.data.userId);

      let roomRecord = await PrivateRoom.findOne({
        code: safeRoom
      }).select("_id name code memberIds");

      if (!roomRecord) {
        return socket.emit(
          "join-error",
          "Room code not found. Check the code and try again."
        );
      }

      const alreadyMember = roomRecord.memberIds.some(
        id => String(id) === String(userObjectId)
      );

      if (!alreadyMember) {
        roomRecord = await PrivateRoom.findOneAndUpdate(
          { _id: roomRecord._id },
          { $addToSet: { memberIds: userObjectId } },
          { new: true }
        ).select("_id name code memberIds");
      }

      if (
        !roomRecord ||
        !roomRecord.memberIds.some(
          id => String(id) === String(userObjectId)
        )
      ) {
        return socket.emit(
          "join-error",
          "Could not add you to this room. Please try again."
        );
      }

      roomRecord = roomRecord.toObject();

      const safeName = socket.data.name;
      const oldRoom = socket.data.room;

      if (oldRoom) {
        socket.leave(oldRoom);

        socket.to(oldRoom).emit("user-typing", {
          name: safeName,
          socketId: socket.id,
          isTyping: false
        });

        broadcastSystem(oldRoom, `${safeName} left the room.`);
        broadcastOnlineUsers(oldRoom);
      }

      socket.data.room = safeRoom;
      socket.data.roomAuthorized = true;
      socket.data.roomName = roomRecord.name;
      socket.data.seenMessages.clear();

      socket.join(safeRoom);

      const history = await loadRoomMessages(safeRoom);

      if (
        socket.data.room !== safeRoom ||
        !socket.data.roomAuthorized
      ) return;

      socket.emit("chat-history", history);

      socket.emit("joined-chat", {
        name: safeName,
        room: safeRoom,
        roomName: roomRecord.name
      });

      broadcastSystem(safeRoom, `${safeName} joined the room.`);
      broadcastOnlineUsers(safeRoom);

    } catch (error) {
      console.error("Room loading error:", error.message);

      socket.emit(
        "join-error",
        "Could not load this room. Please try again."
      );
    }
  });

  // ---------------- TYPING ----------------

  socket.on("typing", async ({ room, isTyping } = {}) => {
    const currentRoom = socket.data.room;

    if (
      !currentRoom ||
      !socket.data.roomAuthorized ||
      cleanRoom(room) !== currentRoom ||
      !socket.rooms.has(currentRoom)
    ) return;

    try {
      if (!(await userIsRoomMember(currentRoom, socket.data.userId))) {
        return;
      }

      socket.to(currentRoom).emit("user-typing", {
        name: socket.data.name,
        socketId: socket.id,
        isTyping: Boolean(isTyping)
      });

    } catch (error) {
      console.error("Typing authorization error:", error.message);
    }
  });

  // ---------------- SEND TEXT MESSAGE ----------------

  socket.on("send-message", async ({ room, text } = {}) => {
    const currentRoom = socket.data.room;
    const messageText = String(text || "").trim();

    if (
      !currentRoom ||
      !socket.data.roomAuthorized ||
      cleanRoom(room) !== currentRoom ||
      !socket.rooms.has(currentRoom) ||
      !messageText ||
      messageText.length > 5000
    ) return;

    try {
      if (!(await userIsRoomMember(currentRoom, socket.data.userId))) {
        return socket.emit(
          "join-error",
          "You no longer have access to this room."
        );
      }

      await addMessage(currentRoom, {
        id: makeMessageId(),
        room: currentRoom,
        name: socket.data.name,
        senderId: socket.id,
        senderUserId: socket.data.userId,
        text: messageText,
        type: "text",
        createdAt: Date.now()
      });

    } catch (error) {
      console.error("Send-message authorization error:", error.message);
    }
  });

  // ---------------- SEND AUDIO MESSAGE ----------------

  socket.on("send-audio", async ({ room, audio, mimeType } = {}) => {
    const currentRoom = socket.data.room;

    if (
      !currentRoom ||
      !socket.data.roomAuthorized ||
      cleanRoom(room) !== currentRoom ||
      !socket.rooms.has(currentRoom)
    ) return;

    try {
      if (!(await userIsRoomMember(currentRoom, socket.data.userId))) {
        return socket.emit(
          "audio-error",
          "You no longer have access to this room."
        );
      }

      let audioBuffer;

      if (Buffer.isBuffer(audio)) {
        audioBuffer = audio;
      } else if (audio instanceof ArrayBuffer) {
        audioBuffer = Buffer.from(audio);
      } else if (ArrayBuffer.isView(audio)) {
        audioBuffer = Buffer.from(
          audio.buffer,
          audio.byteOffset,
          audio.byteLength
        );
      } else {
        return;
      }

      if (!audioBuffer.length || audioBuffer.length > MAX_AUDIO_BYTES) {
        return socket.emit("audio-error", "Audio must be under 1 MB.");
      }

      const allowedTypes = [
        "audio/webm",
        "audio/ogg",
        "audio/mp4",
        "audio/mpeg",
        "audio/webm;codecs=opus"
      ];

      const safeMimeType = allowedTypes.includes(String(mimeType))
        ? String(mimeType)
        : "audio/webm";

      await addMessage(currentRoom, {
        id: makeMessageId(),
        room: currentRoom,
        name: socket.data.name,
        senderId: socket.id,
        senderUserId: socket.data.userId,
        audio: audioBuffer,
        mimeType: safeMimeType,
        type: "audio",
        createdAt: Date.now()
      });

    } catch (error) {
      console.error("Send-audio authorization error:", error.message);
    }
  });

  // ---------------- MARK MESSAGE AS SEEN ----------------

  socket.on("mark-seen", async ({ room, messageId } = {}) => {
    const currentRoom = socket.data.room;

    if (
      !currentRoom ||
      !socket.data.roomAuthorized ||
      cleanRoom(room) !== currentRoom ||
      !socket.rooms.has(currentRoom) ||
      typeof messageId !== "string"
    ) return;

    try {
      if (!(await userIsRoomMember(currentRoom, socket.data.userId))) {
        return;
      }

      const message = await Message.findOne({
        room: currentRoom,
        id: messageId
      });

      if (
        !message ||
        message.senderUserId === socket.data.userId ||
        socket.data.seenMessages.has(messageId)
      ) return;

      socket.data.seenMessages.add(messageId);

      if (!message.seenAt) {
        const now = Date.now();
        const expiresAt = new Date(now + MESSAGE_LIFETIME);

        message.seenAt = now;
        message.expiresAt = expiresAt;

        await message.save();

        const cached = getRoomMessages(currentRoom).find(
          item => item.id === messageId
        );

        if (cached) cached.seenAt = now;

        io.to(currentRoom).emit("message-seen", {
          messageId,
          seenBy: socket.data.name,
          seenById: socket.id
        });

        scheduleExpiry(
          currentRoom,
          messageId,
          expiresAt.getTime()
        );
      }

    } catch (error) {
      console.error("Mark-seen error:", error.message);
    }
  });

  // ---------------- CALL HELPERS ----------------

  function socketHasActiveCall(socketId) {
    return [...activeCalls.values()].some(call =>
      call.callerSocketId === socketId ||
      call.calleeSocketId === socketId
    );
  }

  function getCall(callId) {
    return activeCalls.get(String(callId || ""));
  }

  // ---------------- START AUDIO / VIDEO CALL ----------------

  socket.on("start-audio-call", async ({ targetUserId, callType } = {}) => {
    try {
      const room = socket.data.room;

      if (
        !room ||
        !socket.data.roomAuthorized ||
        !socket.rooms.has(room)
      ) {
        return socket.emit("call-error", "Join a room before calling.");
      }

      if (!targetUserId) {
        return socket.emit(
          "call-error",
          "The other member's account ID is missing."
        );
      }

      if (!["audio", "video"].includes(callType)) {
        return socket.emit("call-error", "Invalid call type.");
      }

      if (socketHasActiveCall(socket.id)) {
        return socket.emit("call-error", "You already have an active call.");
      }

      if (!(await userIsRoomMember(room, socket.data.userId))) {
        return socket.emit(
          "call-error",
          "You are not a member of this room."
        );
      }

      const roomSockets = io.sockets.adapter.rooms.get(room);
      let targetSocket = null;

      if (roomSockets) {
        for (const socketId of roomSockets) {
          const candidate = io.sockets.sockets.get(socketId);

          if (
            candidate &&
            candidate.id !== socket.id &&
            candidate.data.userId === String(targetUserId) &&
            candidate.data.room === room &&
            candidate.data.roomAuthorized
          ) {
            targetSocket = candidate;
            break;
          }
        }
      }

      if (!targetSocket) {
        return socket.emit(
          "call-error",
          "This member is no longer online in this room."
        );
      }

      if (socketHasActiveCall(targetSocket.id)) {
        return socket.emit(
          "call-error",
          "This member is already in another call."
        );
      }

      if (
        !(await userIsRoomMember(room, targetSocket.data.userId))
      ) {
        return socket.emit(
          "call-error",
          "This member no longer has access to this room."
        );
      }

      const callId = crypto.randomUUID();

      const call = {
        callId,
        room,
        callType,
        callerSocketId: socket.id,
        calleeSocketId: targetSocket.id,
        status: "ringing"
      };

      activeCalls.set(callId, call);

      socket.emit("audio-call-ringing", { callId });

      targetSocket.emit("incoming-audio-call", {
        callId,
        callType,
        callerName: socket.data.name || "A room member"
      });

    } catch (error) {
      console.error("Start call error:", error);

      socket.emit(
        "call-error",
        "Could not start the call. Please try again."
      );
    }
  });

  // ---------------- ACCEPT CALL ----------------

  socket.on("accept-audio-call", ({ callId } = {}) => {
    const call = getCall(callId);

    if (
      !call ||
      call.calleeSocketId !== socket.id ||
      call.status !== "ringing"
    ) return;

    call.status = "accepted";

    const caller = io.sockets.sockets.get(call.callerSocketId);

    if (!caller) {
      activeCalls.delete(call.callId);

      return socket.emit("audio-call-ended", {
        callId: call.callId,
        message: "The caller disconnected."
      });
    }

    caller.emit("audio-call-accepted", {
      callId: call.callId,
      callType: call.callType
    });

    socket.emit("audio-call-ready", {
      callId: call.callId,
      callType: call.callType
    });
  });

  // ---------------- REJECT CALL ----------------

  socket.on("reject-audio-call", ({ callId } = {}) => {
    const call = getCall(callId);

    if (
      !call ||
      (
        call.callerSocketId !== socket.id &&
        call.calleeSocketId !== socket.id
      )
    ) return;

    const otherSocketId =
      call.callerSocketId === socket.id
        ? call.calleeSocketId
        : call.callerSocketId;

    const otherSocket = io.sockets.sockets.get(otherSocketId);

    if (otherSocket) {
      otherSocket.emit("audio-call-rejected", {
        callId: call.callId,
        message: "The other member declined the call."
      });
    }

    activeCalls.delete(call.callId);
  });

  // ---------------- SEND WEBRTC OFFER ----------------

  socket.on("audio-call-offer", ({ callId, offer } = {}) => {
    const call = getCall(callId);

    if (
      !call ||
      call.callerSocketId !== socket.id ||
      call.status !== "accepted" ||
      !offer
    ) return;

    const callee = io.sockets.sockets.get(call.calleeSocketId);

    if (!callee) {
      activeCalls.delete(call.callId);

      return socket.emit("audio-call-ended", {
        callId: call.callId,
        message: "The other member disconnected."
      });
    }

    callee.emit("audio-call-offer", {
      callId: call.callId,
      offer
    });
  });

  // ---------------- SEND WEBRTC ANSWER ----------------

  socket.on("audio-call-answer", ({ callId, answer } = {}) => {
    const call = getCall(callId);

    if (
      !call ||
      call.calleeSocketId !== socket.id ||
      call.status !== "accepted" ||
      !answer
    ) return;

    const caller = io.sockets.sockets.get(call.callerSocketId);

    if (caller) {
      caller.emit("audio-call-answer", {
        callId: call.callId,
        answer
      });
    }
  });

  // ---------------- SEND ICE CANDIDATES ----------------

  socket.on("audio-call-ice", ({ callId, candidate } = {}) => {
    const call = getCall(callId);

    if (
      !call ||
      call.status !== "accepted" ||
      !candidate ||
      (
        call.callerSocketId !== socket.id &&
        call.calleeSocketId !== socket.id
      )
    ) return;

    const otherSocketId =
      call.callerSocketId === socket.id
        ? call.calleeSocketId
        : call.callerSocketId;

    const otherSocket = io.sockets.sockets.get(otherSocketId);

    if (otherSocket) {
      otherSocket.emit("audio-call-ice", {
        callId: call.callId,
        candidate
      });
    }
  });

  // ---------------- END CALL ----------------

  socket.on("end-audio-call", ({ callId } = {}) => {
    const call = getCall(callId);

    if (
      !call ||
      (
        call.callerSocketId !== socket.id &&
        call.calleeSocketId !== socket.id
      )
    ) return;

    const otherSocketId =
      call.callerSocketId === socket.id
        ? call.calleeSocketId
        : call.callerSocketId;

    const otherSocket = io.sockets.sockets.get(otherSocketId);

    if (otherSocket) {
      otherSocket.emit("audio-call-ended", {
        callId: call.callId,
        message: "The other member ended the call."
      });
    }

    activeCalls.delete(call.callId);
  });

  // ---------------- DISCONNECT ----------------

  socket.on("disconnect", () => {

    // Clean up any active calls first.
    for (const [callId, call] of activeCalls.entries()) {
      if (
        call.callerSocketId === socket.id ||
        call.calleeSocketId === socket.id
      ) {
        const otherSocketId =
          call.callerSocketId === socket.id
            ? call.calleeSocketId
            : call.callerSocketId;

        const otherSocket = io.sockets.sockets.get(otherSocketId);

        if (otherSocket) {
          otherSocket.emit("audio-call-ended", {
            callId,
            message: "The other member disconnected."
          });
        }

        activeCalls.delete(callId);
      }
    }

    const room = socket.data.room;

    if (!room || !socket.data.roomAuthorized) return;

    socket.to(room).emit("user-typing", {
      name: socket.data.name,
      socketId: socket.id,
      isTyping: false
    });

    broadcastSystem(room, `${socket.data.name} disconnected.`);
    broadcastOnlineUsers(room);
  });

});

// ---------------- START SERVER ----------------
async function startServer() {
  try {
    await mongoose.connect(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 10000 });
    await Message.init();
    await PrivateRoom.init();
    await RoomRequest.init();

    // Preserve access to existing message history: for old rooms with messages but
    // no PrivateRoom record, create a room using the earliest sender as owner and
    // previous senders as members. Rooms without messages are not migrated.
    const oldRoomCodes = await Message.distinct("room");
    let migratedCount = 0;
    for (const oldCode of oldRoomCodes) {
      if (!oldCode || await PrivateRoom.exists({ code: oldCode })) continue;
      const oldMessages = await Message.find({ room: oldCode }).sort({ createdAt: 1 }).select("senderUserId").lean();
      const candidateIds = [...new Set(oldMessages.map(message => String(message.senderUserId || "")).filter(id => mongoose.Types.ObjectId.isValid(id)))];
      if (!candidateIds.length) continue;
      const users = await User.find({ _id: { $in: candidateIds } }).select("_id").lean();
      const validIds = users.map(user => user._id);
      if (!validIds.length) continue;
      const firstSenderId = String(oldMessages[0].senderUserId);
      const owner = validIds.find(id => String(id) === firstSenderId) || validIds[0];
      try {
        await PrivateRoom.create({ name: `Previous room ${oldCode}`.slice(0, 50), code: oldCode, ownerId: owner, memberIds: validIds, invitations: [] });
        migratedCount++;
      } catch (error) {
        if (error.code !== 11000) console.error(`Could not migrate previous room ${oldCode}:`, error.message);
      }
    }

    const expiringMessages = await Message.find({ expiresAt: { $exists: true, $ne: null } }).select("id room expiresAt").lean();
    for (const message of expiringMessages) scheduleExpiry(message.room, message.id, message.expiresAt.getTime());
    console.log("MongoDB connected successfully!");
    console.log(`Restored ${expiringMessages.length} message expiry timer(s).`);
    console.log(`Prepared ${migratedCount} previous room(s) for member-only access.`);
    server.listen(PORT, () => console.log(`5M Chat running at http://localhost:${PORT}`));
  } catch (error) {
    console.error("Could not start 5M Chat:", error.message);
    process.exit(1);
  }
}
startServer();
