
require("dotenv").config();
const { rateLimit } = require("express-rate-limit");
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
app.set("trust proxy", 1);
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
app.use(express.json({ limit: "300kb" }));
app.use(express.urlencoded({ extended: false }));
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: "Too many authentication attempts. Please wait 15 minutes and try again."
  }
});
if (!process.env.SESSION_SECRET) {
  throw new Error("SESSION_SECRET is missing from your .env file.");
}
if (!process.env.MONGODB_URI) {
  throw new Error("MONGODB_URI is missing from your .env file.");
}

// ---------------- DATABASE MODELS ----------------

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 30 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true, maxlength: 254 },
  passwordHash: { type: String, required: true, select: false },

  avatarType: {
    type: String,
    enum: ["emoji", "photo"],
    default: "emoji"
  },
   avatarValue: {
    type: String,
    default: "😎",
    maxlength: 280000
  },
  bio: {
    type: String,
    default: "Available to chat",
    trim: true,
    maxlength: 120
  }
}, { timestamps: true });

const User = mongoose.model("User", userSchema);

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

const messageSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  room: { type: String, required: true, index: true },
  name: { type: String, required: true },
  senderId: { type: String, required: true },
  senderUserId: { type: String, required: true },
  senderAvatarType: {
  type: String,
  enum: ["emoji", "photo"],
  default: "emoji"
},
senderAvatarValue: {
  type: String,
  default: "😎",
  maxlength: 280000
},
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
      return res.status(401).json({
        success: false,
        message: "Please log in."
      });
    }
    return res.redirect("/login.html");
  }
  next();
}

function cleanRoom(value) {
  return String(value || "")
    .trim()
    .replace(/[^a-zA-Z0-9_-]/g, "")
    .slice(0, 40);
}

function cleanName(value) {
  return String(value || "Guest")
    .trim()
    .replace(/\s+/g, " ")
    .slice(0, 30) || "Guest";
}

function validEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}
function publicUser(user) {
  return {
    id: String(user._id),
    name: user.name,
    email: user.email,
    avatarType: user.avatarType || "emoji",
    avatarValue: user.avatarValue || "😎",
    bio: user.bio || "Available to chat"
  };
}
function regenerateSession(req) {
  return new Promise((resolve, reject) => {
    req.session.regenerate(error => error ? reject(error) : resolve());
  });
}

function saveSession(req) {
  return new Promise((resolve, reject) => {
    req.session.save(error => error ? reject(error) : resolve());
  });
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

// FIX: This membership helper was missing from the supplied file.
async function userIsRoomMember(roomCode, userId) {
  if (!roomCode || !userId || !mongoose.Types.ObjectId.isValid(userId)) {
    return false;
  }

  return Boolean(await PrivateRoom.exists({
    code: roomCode,
    memberIds: userId
  }));
}

function toMessagePayload(doc) {
  const message = doc.toObject ? doc.toObject() : doc;

  return {
    id: message.id,
    room: message.room,
    name: message.name,
    senderId: message.senderId,
    senderUserId: message.senderUserId,
    senderAvatarType: message.senderAvatarType || "emoji",
    senderAvatarValue: message.senderAvatarValue || "😎",
    text: message.text || "",
    ...(message.audio ? { audio: message.audio } : {}),
    ...(message.mimeType ? { mimeType: message.mimeType } : {}),
    type: message.type,
    createdAt: message.createdAt,
    seenAt: message.seenAt || null
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
  id: connectedSocket.id,
  socketId: connectedSocket.id,
  userId: connectedSocket.data.userId,
  name: connectedSocket.data.name || "User",
  avatarType: connectedSocket.data.avatarType || "emoji",
  avatarValue: connectedSocket.data.avatarValue || "😎"
});
      }
    }
  }

  io.to(room).emit("online-users", users);
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

  const timer = setTimeout(() => {
    expiryTimers.delete(key);
    removeMessage(room, messageId);
  }, remaining);

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
    if (document.expiresAt) {
      scheduleExpiry(room, document.id, document.expiresAt.getTime());
    }
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

app.post("/api/auth/register", authLimiter, async (req, res) => {
  try {
    const name = cleanName(req.body.name);
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (
      name === "Guest" || name.length < 2 ||
      !validEmail(email) || email.length > 254 ||
      password.length < 8 || Buffer.byteLength(password, "utf8") > 72
    ) {
      return res.status(400).json({
        success: false,
        message: "Enter a name of 2–30 characters, a valid email, and a password of 8–72 bytes."
      });
    }

    const existing = await User.findOne({ email }).lean();

    if (existing) {
      return res.status(409).json({
        success: false,
        message: "An account with this email already exists."
      });
    }

    const user = await User.create({
      name,
      email,
      passwordHash: await bcrypt.hash(password, 12)
    });

    await startLoginSession(req, user);

    res.status(201).json({ success: true, user: publicUser(user) });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({
        success: false,
        message: "An account with this email already exists."
      });
    }

    console.error("Registration error:", error.message);
    res.status(500).json({
      success: false,
      message: "Could not create your account. Please try again."
    });
  }
});

app.post("/api/auth/login", authLimiter, async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (
      !validEmail(email) || email.length > 254 ||
      !password || Buffer.byteLength(password, "utf8") > 72
    ) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid email and password."
      });
    }

    const user = await User.findOne({ email }).select("+passwordHash");

    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).json({
        success: false,
        message: "Incorrect email or password."
      });
    }

    await startLoginSession(req, user);
    res.json({ success: true, user: publicUser(user) });
  } catch (error) {
    console.error("Login error:", error.message);
    res.status(500).json({
      success: false,
      message: "Could not log in. Please try again."
    });
  }
});

app.get("/api/auth/me", async (req, res) => {
  try {
    if (!req.session.userId) {
      return res.status(401).json({ success: false, message: "Please log in." });
    }

    const user = await User.findById(req.session.userId);

    if (!user) {
      return req.session.destroy(() =>
        res.status(401).json({ success: false, message: "Please log in again." })
      );
    }

    res.json({ success: true, user: publicUser(user) });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Could not check your account."
    });
  }
});

app.post("/api/auth/logout", (req, res) => {
  if (!req.session) return res.json({ success: true });

  req.session.destroy(error => {
    if (error) {
      return res.status(500).json({ success: false, message: "Could not log out." });
    }

    res.clearCookie("fiveMChat.sid", {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production"
    });

    res.json({ success: true });
  });
});

app.put("/api/profile", requireAuth, async (req, res) => {
  try {
    const avatarType = req.body.avatarType;
    const avatarValue = req.body.avatarValue;
    const bio = typeof req.body.bio === "string"
  ? req.body.bio.trim()
  : undefined;

if (bio !== undefined && bio.length > 120) {
  return res.status(400).json({
    success: false,
    message: "Bio must be 120 characters or fewer."
  });
}

    if (!["emoji", "photo"].includes(avatarType)) {
      return res.status(400).json({
        success: false,
        message: "Choose an emoji or photo avatar."
      });
    }

    if (typeof avatarValue !== "string" || !avatarValue.trim()) {
      return res.status(400).json({
        success: false,
        message: "Please choose an avatar."
      });
    }

    if (avatarType === "emoji") {
      if ([...avatarValue].length > 12) {
        return res.status(400).json({
          success: false,
          message: "Please choose a shorter emoji."
        });
      }
    } else {
      const validPhoto = /^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/]+={0,2}$/.test(avatarValue);

      if (!validPhoto || avatarValue.length > 280000) {
        return res.status(400).json({
          success: false,
          message: "Use a valid JPEG, PNG, or WebP photo under the size limit."
        });
      }
    }
const updates = { avatarType, avatarValue };

if (bio !== undefined) {
  updates.bio = bio;
}

const user = await User.findByIdAndUpdate(
  req.session.userId,
  { $set: updates },
  { new: true, runValidators: true }
);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "Account not found. Please log in again."
      });
    }

    res.json({
      success: true,
      message: "Profile avatar saved!",
      user: publicUser(user)
    });
  } catch (error) {
    console.error("Profile update error:", error);
    res.status(500).json({
      success: false,
      message: "Could not save your profile avatar."
    });
  }
});

// ---------------- PRIVATE ROOM API ----------------

app.post("/api/rooms", requireAuth, async (req, res) => {
  try {
    const roomName = String(req.body.name || "").trim();

    if (!roomName || roomName.length > 50) {
      return res.status(400).json({
        success: false,
        message: "Room name must be between 1 and 50 characters."
      });
    }

    let roomCode;
    let exists;

    do {
      roomCode = crypto.randomBytes(4).toString("hex").toUpperCase();
      exists = await PrivateRoom.findOne({ code: roomCode }).select("_id").lean();
    } while (exists);

    const newRoom = await PrivateRoom.create({
      name: roomName,
      code: roomCode,
      ownerId: req.session.userId,
      memberIds: [req.session.userId],
      invitations: []
    });

    res.status(201).json({
      success: true,
      message: "Private room created successfully.",
      room: {
        id: String(newRoom._id),
        name: newRoom.name,
        code: newRoom.code,
        owner: true
      }
    });
  } catch (error) {
    console.error("Create room error:", error.message);
    res.status(500).json({
      success: false,
      message: "Could not create the private room."
    });
  }
});

app.get("/api/rooms", requireAuth, async (req, res) => {
  try {
    const list = await PrivateRoom.find({
      memberIds: req.session.userId
    }).sort({ updatedAt: -1 }).lean();

    res.json({
      success: true,
      rooms: list.map(room => ({
        id: String(room._id),
        name: room.name,
        code: room.code,
        owner: String(room.ownerId) === String(req.session.userId)
      }))
    });
  } catch (error) {
    console.error("List rooms error:", error.message);
    res.status(500).json({
      success: false,
      message: "Could not load your rooms."
    });
  }
});
app.delete("/api/rooms/:id", requireAuth, async (req, res) => {
  try {
    const room = await PrivateRoom.findById(req.params.id);

    if (!room) {
      return res.status(404).json({
        success: false,
        message: "Room not found."
      });
    }

    // Only the room owner can delete it.
    if (String(room.ownerId) !== String(req.session.userId)) {
      return res.status(403).json({
        success: false,
        message: "Only the room owner can delete this room."
      });
    }

    const roomCode = room.code;
    const roomId = String(room._id);

    // Delete database records.
    await Promise.all([
      Message.deleteMany({ room: roomCode }),
      RoomRequest.deleteMany({ roomId: room._id }),
      PrivateRoom.deleteOne({ _id: room._id })
    ]);

    // Clear message-expiry timers for this room.
    for (const [key, timer] of expiryTimers.entries()) {
      if (key.startsWith(`${roomCode}:`)) {
        clearTimeout(timer);
        expiryTimers.delete(key);
      }
    }

    // Remove cached messages.
    rooms.delete(roomCode);

    // End active calls belonging to this room.
    for (const [callId, call] of activeCalls.entries()) {
      if (call.room === roomCode) {
        activeCalls.delete(callId);

        io.to(call.callerSocketId).emit("audio-call-ended", {
          callId,
          message: "This room has been deleted."
        });

        io.to(call.calleeSocketId).emit("audio-call-ended", {
          callId,
          message: "This room has been deleted."
        });
      }
    }

    // Remove connected users from the deleted room.
    const connectedSockets = await io.in(roomCode).fetchSockets();

    for (const connectedSocket of connectedSockets) {
      connectedSocket.data.room = null;
      connectedSocket.data.roomAuthorized = false;
      connectedSocket.data.roomName = null;

      await connectedSocket.leave(roomCode);
    }

    // Notify all connected clients.
    io.emit("room-deleted", { roomId });

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

// Room requests by registered email.
app.post("/api/rooms/:code/request", requireAuth, async (req, res) => {
  try {
    const code = cleanRoom(req.params.code).toUpperCase();
    const email = String(req.body.email || "").trim().toLowerCase();

    if (!validEmail(email) || email.length > 254) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid email address."
      });
    }

    const room = await PrivateRoom.findOne({ code });

    if (!room) {
      return res.status(404).json({ success: false, message: "Room not found." });
    }

    if (String(room.ownerId) !== String(req.session.userId)) {
      return res.status(403).json({
        success: false,
        message: "Only the room owner can send room requests."
      });
    }

    const recipient = await User.findOne({ email }).select("_id name email");

    if (!recipient) {
      return res.status(404).json({
        success: false,
        message: "That email is not registered on 5M Chat."
      });
    }

    if (String(recipient._id) === String(req.session.userId)) {
      return res.status(400).json({
        success: false,
        message: "You cannot send a request to yourself."
      });
    }

    if (room.memberIds.some(id => String(id) === String(recipient._id))) {
      return res.status(409).json({
        success: false,
        message: "This user is already a room member."
      });
    }

    const existing = await RoomRequest.findOne({
      roomId: room._id,
      recipientId: recipient._id,
      status: "pending"
    });

    if (existing) {
      return res.status(409).json({
        success: false,
        message: "A request is already waiting for this user."
      });
    }

    const request = await RoomRequest.create({
      roomId: room._id,
      roomCode: room.code,
      roomName: room.name,
      senderId: req.session.userId,
      recipientId: recipient._id,
      status: "pending"
    });

    io.to(`user:${String(recipient._id)}`).emit("room-request", {
      id: String(request._id),
      roomCode: room.code,
      roomName: room.name,
      senderName: req.session.name || "Someone"
    });

    res.status(201).json({
      success: true,
      message: "Room request sent successfully."
    });
  } catch (error) {
    console.error("Send room request error:", error.message);
    res.status(500).json({
      success: false,
      message: "Could not send the room request."
    });
  }
});

app.get("/api/requests", requireAuth, async (req, res) => {
  try {
    const requests = await RoomRequest.find({
      recipientId: req.session.userId,
      status: "pending"
    }).sort({ createdAt: -1 }).lean();

    const result = await Promise.all(requests.map(async request => {
      const sender = await User.findById(request.senderId)
        .select("name email").lean();

      return {
        id: String(request._id),
        roomId: String(request.roomId),
        roomCode: request.roomCode,
        roomName: request.roomName,
        senderName: sender?.name || "Someone",
        senderEmail: sender?.email || ""
      };
    }));

    res.json({ success: true, requests: result });
  } catch (error) {
    console.error("Load room requests error:", error.message);
    res.status(500).json({
      success: false,
      message: "Could not load room requests."
    });
  }
});

async function respondToRoomRequest(req, res, action) {
  try {
    const request = await RoomRequest.findOne({
      _id: req.params.id,
      recipientId: req.session.userId,
      status: "pending"
    });

    if (!request) {
      return res.status(404).json({
        success: false,
        message: "This room request is no longer available."
      });
    }

    if (action === "accept") {
      const room = await PrivateRoom.findById(request.roomId);

      if (!room) {
        request.status = "rejected";
        await request.save();

        return res.status(404).json({
          success: false,
          message: "This room no longer exists."
        });
      }

      if (!room.memberIds.some(id => String(id) === String(req.session.userId))) {
        room.memberIds.push(req.session.userId);
        await room.save();
      }

      request.status = "accepted";
      await request.save();

      return res.json({
        success: true,
        message: "Request accepted. You have joined the room."
      });
    }

    request.status = "rejected";
    await request.save();

    res.json({ success: true, message: "Room request rejected." });
  } catch (error) {
    console.error(`Room request ${action} error:`, error.message);
    res.status(500).json({
      success: false,
      message: "Could not process this room request."
    });
  }
}

app.post("/api/requests/:id/accept", requireAuth, (req, res) =>
  respondToRoomRequest(req, res, "accept")
);
app.post("/api/requests/:id/reject", requireAuth, (req, res) =>
  respondToRoomRequest(req, res, "reject")
);

// Legacy token invitations.
app.post("/api/rooms/:code/invite", requireAuth, async (req, res) => {
  try {
    const code = cleanRoom(req.params.code);
    const email = String(req.body.email || "").trim().toLowerCase();

    if (!validEmail(email) || email.length > 254) {
      return res.status(400).json({
        success: false,
        message: "Please enter a valid email address."
      });
    }

    const room = await PrivateRoom.findOne({ code });

    if (!room) {
      return res.status(404).json({
        success: false,
        message: "Private room not found."
      });
    }

    if (String(room.ownerId) !== String(req.session.userId)) {
      return res.status(403).json({
        success: false,
        message: "Only the room owner can invite users."
      });
    }

    const invitedUser = await User.findOne({ email }).select("_id email");

    if (!invitedUser) {
      return res.status(404).json({
        success: false,
        message: "That email is not registered on 5M Chat yet."
      });
    }

    if (room.memberIds.some(id => String(id) === String(invitedUser._id))) {
      return res.status(409).json({
        success: false,
        message: "This user is already a room member."
      });
    }

    const token = crypto.randomBytes(32).toString("hex");
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

    room.invitations = room.invitations.filter(item => item.email !== email);
    room.invitations.push({
      email,
      tokenHash,
      createdAt: new Date(),
      acceptedAt: null
    });

    await room.save();

    res.json({
      success: true,
      message: "Invitation created. Share this token privately with the invited user.",
      invitationToken: token,
      roomName: room.name,
      roomCode: room.code,
      invitedEmail: email
    });
  } catch (error) {
    console.error("Invite user error:", error.message);
    res.status(500).json({
      success: false,
      message: "Could not invite this user."
    });
  }
});

app.post("/api/rooms/:code/accept", requireAuth, async (req, res) => {
  try {
    const code = cleanRoom(req.params.code);
    const token = String(req.body.token || "").trim();

    if (!token || token.length > 200) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid invitation token."
      });
    }

    const user = await User.findById(req.session.userId).select("email");

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Please log in again."
      });
    }

    const room = await PrivateRoom.findOne({ code });

    if (!room) {
      return res.status(404).json({
        success: false,
        message: "Private room not found."
      });
    }

    if (room.memberIds.some(id => String(id) === String(user._id))) {
      return res.json({
        success: true,
        message: "You are already a room member.",
        room: { name: room.name, code: room.code }
      });
    }

    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    const invitation = room.invitations.find(item =>
      item.email === user.email &&
      item.tokenHash === tokenHash &&
      !item.acceptedAt
    );

    if (!invitation) {
      return res.status(403).json({
        success: false,
        message: "This invitation is invalid, already used, or belongs to another email account."
      });
    }

    invitation.acceptedAt = new Date();
    room.memberIds.push(user._id);
    await room.save();

    res.json({
      success: true,
      message: "Invitation accepted. You can now join the private room.",
      room: { name: room.name, code: room.code }
    });
  } catch (error) {
    console.error("Accept invitation error:", error.message);
    res.status(500).json({
      success: false,
      message: "Could not accept the invitation."
    });
  }
});

// ---------------- PAGE ROUTES ----------------

app.get("/", (req, res) => {
  if (req.session && req.session.userId) {
    return res.redirect("/chat.html");
  }
  return res.redirect("/login.html");
});

app.get("/login.html", (req, res) => {
  if (req.session && req.session.userId) {
    return res.redirect("/chat.html");
  }
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.get("/chat.html", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "chat.html"));
});

app.get("/api/status", (req, res) => {
  res.json({
    success: true,
    message: "5M Chat backend is working!",
    database: mongoose.connection.readyState === 1
      ? "connected"
      : "disconnected"
  });
});

// ---------------- SOCKET AUTHENTICATION ----------------

io.use(async (socket, next) => {
  try {
    const sessionData = socket.request.session;

    if (!sessionData || !sessionData.userId) {
      return next(new Error("Please log in to use 5M Chat."));
    }

    const user = await User.findById(sessionData.userId)
      .select("name avatarType avatarValue");

    if (!user) {
      return next(new Error("Please log in again."));
    }

    socket.data.userId = String(user._id);
    socket.data.name = cleanName(user.name);
    socket.data.avatarType = user.avatarType || "emoji";
    socket.data.avatarValue = user.avatarValue || "😎";

    socket.join(`user:${socket.data.userId}`);

    next();
  } catch (error) {
    console.error("Socket authentication error:", error);
    next(new Error("Could not authenticate your account."));
  }
});


// Clean up a call when either participant disconnects or changes rooms.
function endCallsForSocket(socket) {
  for (const [callId, call] of activeCalls) {
    if (call.callerSocketId !== socket.id && call.calleeSocketId !== socket.id) {
      continue;
    }

    activeCalls.delete(callId);

    const peerSocketId = call.callerSocketId === socket.id
      ? call.calleeSocketId
      : call.callerSocketId;

    io.to(peerSocketId).emit("audio-call-ended", { callId });
    socket.emit("audio-call-ended", { callId });
  }
}

io.on("connection", socket => {
  socket.data.room = null;
  socket.data.roomAuthorized = false;
  socket.data.seenMessages = new Set();

  socket.on("join-chat", async ({ room } = {}) => {
    try {
      const safeRoom = cleanRoom(room);

      if (!safeRoom) {
        return socket.emit("join-error", "Enter a valid room code.");
      }

      const roomRecord = await PrivateRoom.findOne({
        code: safeRoom,
        memberIds: socket.data.userId
      }).select("name code").lean();

      if (!roomRecord) {
        return socket.emit(
          "join-error",
          "You are not a member of this private room. Ask its owner for an invitation."
        );
      }

      const safeName = socket.data.name;
      const oldRoom = socket.data.room;

      if (oldRoom) {
        endCallsForSocket(socket);

        socket.to(oldRoom).emit("user-typing", {
          name: safeName,
          socketId: socket.id,
          isTyping: false
        });

        socket.leave(oldRoom);
        broadcastSystem(oldRoom, `${safeName} left the room.`);
        broadcastOnlineUsers(oldRoom);
      }

      socket.data.room = safeRoom;
      socket.data.roomAuthorized = true;
      socket.data.roomName = roomRecord.name;
      socket.data.seenMessages.clear();

      socket.join(safeRoom);

      const history = await loadRoomMessages(safeRoom);

      if (socket.data.room !== safeRoom || !socket.data.roomAuthorized) return;

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
      socket.emit("join-error", "Could not load this room. Please try again.");
    }
  });

  socket.on("typing", async ({ room, isTyping } = {}) => {
    const currentRoom = socket.data.room;

    if (
      !currentRoom || !socket.data.roomAuthorized ||
      cleanRoom(room) !== currentRoom || !socket.rooms.has(currentRoom)
    ) return;

    try {
      if (!(await userIsRoomMember(currentRoom, socket.data.userId))) return;

      socket.to(currentRoom).emit("user-typing", {
        name: socket.data.name,
        socketId: socket.id,
        isTyping: Boolean(isTyping)
      });
    } catch (error) {
      console.error("Typing authorization error:", error.message);
    }
  });

  socket.on("send-message", async ({ room, text } = {}) => {
    console.log("SEND MESSAGE EVENT:", {
  room,
  user: socket.data.userId,
  text
});
    const currentRoom = socket.data.room;
    const messageText = String(text || "").trim();

    if (
      !currentRoom || !socket.data.roomAuthorized ||
      cleanRoom(room) !== currentRoom || !socket.rooms.has(currentRoom) ||
      !messageText || messageText.length > 5000
    ) return;

    try {
      if (!(await userIsRoomMember(currentRoom, socket.data.userId))) {
        return socket.emit("join-error", "You no longer have access to this room.");
      }

      await addMessage(currentRoom, {
        id: makeMessageId(),
        room: currentRoom,
        name: socket.data.name,
        senderId: socket.id,
        senderUserId: socket.data.userId,
        senderAvatarType: socket.data.avatarType || "emoji",
        senderAvatarValue: socket.data.avatarValue || "😎",
        text: messageText,
        type: "text",
        createdAt: Date.now()
      });
    } catch (error) {
      console.error("Send-message authorization error:", error.message);
    }
  });

  socket.on("send-audio", async ({ room, audio, mimeType } = {}) => {
    const currentRoom = socket.data.room;

    if (
      !currentRoom || !socket.data.roomAuthorized ||
      cleanRoom(room) !== currentRoom || !socket.rooms.has(currentRoom)
    ) return;

    try {
      if (!(await userIsRoomMember(currentRoom, socket.data.userId))) {
        return socket.emit("audio-error", "You no longer have access to this room.");
      }

      let audioBuffer;

      if (Buffer.isBuffer(audio)) {
        audioBuffer = audio;
      } else if (audio instanceof ArrayBuffer) {
        audioBuffer = Buffer.from(audio);
      } else if (ArrayBuffer.isView(audio)) {
        audioBuffer = Buffer.from(audio.buffer, audio.byteOffset, audio.byteLength);
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
        senderAvatarType: socket.data.avatarType || "emoji",
        senderAvatarValue: socket.data.avatarValue || "😎",
        audio: audioBuffer,
        mimeType: safeMimeType,
        type: "audio",
        createdAt: Date.now()
      });
    } catch (error) {
      console.error("Send-audio authorization error:", error.message);
    }
  });

  socket.on("mark-seen", async ({ room, messageId } = {}) => {
    const currentRoom = socket.data.room;

    if (
      !currentRoom || !socket.data.roomAuthorized ||
      cleanRoom(room) !== currentRoom || !socket.rooms.has(currentRoom) ||
      typeof messageId !== "string"
    ) return;

    try {
      if (!(await userIsRoomMember(currentRoom, socket.data.userId))) return;

      const message = await Message.findOne({ room: currentRoom, id: messageId });

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

        const cached = getRoomMessages(currentRoom).find(item => item.id === messageId);
        if (cached) cached.seenAt = now;

        io.to(currentRoom).emit("message-seen", {
          messageId,
          seenBy: socket.data.name,
          seenById: socket.id
        });

        scheduleExpiry(currentRoom, messageId, expiresAt.getTime());
      }
    } catch (error) {
      console.error("Mark-seen error:", error.message);
    }
  });

  // ---------------- LIVE AUDIO CALL SIGNALING ----------------

  socket.on("start-audio-call", async ({
  targetUserId,
  callType = "audio"
} = {}) => {
  if (!["audio", "video"].includes(callType)) {
    return socket.emit("call-error", "Invalid call type.");
  }
    try {
      const room = socket.data.room;
      const callerId = socket.data.userId;
      const targetId = String(targetUserId || "");

      if (
        !room || !socket.data.roomAuthorized || !socket.rooms.has(room) ||
        !targetId || targetId === callerId
      ) {
        return socket.emit("call-error", "Cannot start this call.");
      }

      if (
        !(await userIsRoomMember(room, callerId)) ||
        !(await userIsRoomMember(room, targetId))
      ) {
        return socket.emit(
          "call-error",
          "Calls are only allowed between members of this room."
        );
      }

      for (const call of activeCalls.values()) {
        if (
          call.callerSocketId === socket.id ||
          call.calleeSocketId === socket.id
        ) {
          return socket.emit("call-error", "Finish your current call first.");
        }

        if (
          call.callerUserId === targetId ||
          call.calleeUserId === targetId
        ) {
          return socket.emit("call-error", "That member is already in a call.");
        }
      }

      const targets = await io.in(`user:${targetId}`).fetchSockets();
      const target = targets.find(peer =>
        peer.data.room === room &&
        peer.data.roomAuthorized &&
        peer.rooms.has(room)
      );

      if (!target) {
        return socket.emit("call-error", "That member is not online in this room.");
      }

      const callId = makeMessageId();

     activeCalls.set(callId, {
  callerSocketId: socket.id,
  callerUserId: callerId,
  callerName: socket.data.name,
  calleeSocketId: target.id,
  calleeUserId: targetId,
  room,
  callType
});
target.emit("incoming-audio-call", {
  callId,
  callerId,
  callerName: socket.data.name,
  callType
});
      socket.emit("audio-call-ringing", { callId, targetUserId: targetId });
    } catch (error) {
      console.error("Start-call error:", error.message);
      socket.emit("call-error", "Could not start the call.");
    }
  });

  socket.on("accept-audio-call", async ({ callId } = {}) => {
    const id = String(callId || "");
    const call = activeCalls.get(id);

    if (
      !call || call.calleeSocketId !== socket.id ||
      socket.data.room !== call.room || !socket.data.roomAuthorized
    ) {
      return socket.emit("call-error", "This call is no longer available.");
    }

    try {
      if (!(await userIsRoomMember(call.room, socket.data.userId))) {
        endCall(id);
        return socket.emit("call-error", "You no longer have access to this room.");
      }

      io.to(call.callerSocketId).emit("audio-call-accepted", {
        callId: id,
        peerName: socket.data.name
      });

      socket.emit("audio-call-ready", {
        callId: id,
        peerName: call.callerName
      });
    } catch (error) {
      console.error("Accept-call error:", error.message);
      socket.emit("call-error", "Could not accept this call.");
    }
  });

  function endCall(id, message) {
    const call = activeCalls.get(id);
    if (!call) return;

    activeCalls.delete(id);

    io.to(call.callerSocketId).emit("audio-call-ended", {
      callId: id,
      ...(message ? { message } : {})
    });

    io.to(call.calleeSocketId).emit("audio-call-ended", {
      callId: id,
      ...(message ? { message } : {})
    });
  }

  socket.on("reject-audio-call", ({ callId } = {}) => {
    const id = String(callId || "");
    const call = activeCalls.get(id);

    if (!call || call.calleeSocketId !== socket.id) return;

    activeCalls.delete(id);

    io.to(call.callerSocketId).emit("audio-call-rejected", {
      callId: id,
      message: `${socket.data.name} declined the call.`
    });
  });

  socket.on("audio-call-offer", async ({ callId, offer } = {}) => {
    const id = String(callId || "");
    const call = activeCalls.get(id);

    if (
      !call || call.callerSocketId !== socket.id ||
      socket.data.room !== call.room || !socket.data.roomAuthorized || !offer
    ) return;

    try {
      if (!(await userIsRoomMember(call.room, socket.data.userId))) {
        endCall(id, "Room membership could not be verified.");
        return;
      }

      io.to(call.calleeSocketId).emit("audio-call-offer", {
        callId: id,
        offer
      });
    } catch (error) {
      console.error("Call-offer authorization error:", error.message);
      endCall(id, "Could not relay the call offer.");
    }
  });

  socket.on("audio-call-answer", async ({ callId, answer } = {}) => {
    const id = String(callId || "");
    const call = activeCalls.get(id);

    if (
      !call || call.calleeSocketId !== socket.id ||
      socket.data.room !== call.room || !socket.data.roomAuthorized || !answer
    ) return;

    try {
      if (!(await userIsRoomMember(call.room, socket.data.userId))) {
        endCall(id, "Room membership could not be verified.");
        return;
      }

      io.to(call.callerSocketId).emit("audio-call-answer", {
        callId: id,
        answer
      });
    } catch (error) {
      console.error("Call-answer authorization error:", error.message);
      endCall(id, "Could not relay the call answer.");
    }
  });

  socket.on("audio-call-ice", async ({ callId, candidate } = {}) => {
    const id = String(callId || "");
    const call = activeCalls.get(id);

    if (!call || !candidate) return;

    let recipient;

    if (call.callerSocketId === socket.id) {
      recipient = call.calleeSocketId;
    } else if (call.calleeSocketId === socket.id) {
      recipient = call.callerSocketId;
    } else {
      return;
    }

    if (socket.data.room !== call.room || !socket.data.roomAuthorized) return;

    try {
      if (!(await userIsRoomMember(call.room, socket.data.userId))) {
        endCall(id, "Room membership could not be verified.");
        return;
      }

      io.to(recipient).emit("audio-call-ice", {
        callId: id,
        candidate
      });
    } catch (error) {
      console.error("ICE authorization error:", error.message);
      endCall(id, "Could not relay connection information.");
    }
  });

  socket.on("end-audio-call", ({ callId } = {}) => {
    const id = String(callId || "");
    const call = activeCalls.get(id);

    if (
      !call ||
      (call.callerSocketId !== socket.id && call.calleeSocketId !== socket.id)
    ) return;

    endCall(id);
  });

  socket.on("disconnect", () => {
    // Always clean up calls, even if the socket has no current room.
    endCallsForSocket(socket);

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
    await mongoose.connect(process.env.MONGODB_URI, {
      serverSelectionTimeoutMS: 10000
    });

    await Message.init();
    await PrivateRoom.init();
    await RoomRequest.init();

    // Preserve legacy message rooms by preparing member-only room records.
    const oldRoomCodes = await Message.distinct("room");
    let migratedCount = 0;

    for (const oldCode of oldRoomCodes) {
      if (!oldCode || await PrivateRoom.exists({ code: oldCode })) continue;

      const oldMessages = await Message.find({ room: oldCode })
        .sort({ createdAt: 1 })
        .select("senderUserId")
        .lean();

      const candidateIds = [
        ...new Set(
          oldMessages
            .map(message => String(message.senderUserId || ""))
            .filter(id => mongoose.Types.ObjectId.isValid(id))
        )
      ];

      if (!candidateIds.length) continue;

      const users = await User.find({
        _id: { $in: candidateIds }
      }).select("_id").lean();

      const validIds = users.map(user => user._id);
      if (!validIds.length) continue;

      const firstSenderId = String(oldMessages[0].senderUserId);
      const owner = validIds.find(id => String(id) === firstSenderId) || validIds[0];

      try {
        await PrivateRoom.create({
          name: `Previous room ${oldCode}`.slice(0, 50),
          code: oldCode,
          ownerId: owner,
          memberIds: validIds,
          invitations: []
        });

        migratedCount++;
      } catch (error) {
        if (error.code !== 11000) {
          console.error(`Could not migrate previous room ${oldCode}:`, error.message);
        }
      }
    }

    const expiringMessages = await Message.find({
      expiresAt: { $exists: true, $ne: null }
    }).select("id room expiresAt").lean();

    for (const message of expiringMessages) {
      scheduleExpiry(message.room, message.id, message.expiresAt.getTime());
    }

    console.log("MongoDB connected successfully!");
    console.log(`Restored ${expiringMessages.length} message expiry timer(s).`);
    console.log(`Prepared ${migratedCount} previous room(s) for member-only access.`);

    server.listen(PORT, () => {
      console.log(`5M Chat running at http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error("Could not start 5M Chat:", error.message);
    process.exit(1);
  }
}

startServer();
