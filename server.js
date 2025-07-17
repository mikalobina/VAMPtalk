require('dotenv').config();
const express = require("express");
const http = require("http");
const { ExpressPeerServer } = require("peer");
const socketIO = require("socket.io");
const path = require("path");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const mongoose = require("mongoose");
const User = require("./models/User");

const app = express();
const server = http.createServer(app);

// PeerJS Server Setup
const peerServer = ExpressPeerServer(server, {
    debug: true,
    path: '/peerjs'
});
app.use(peerServer);

const io = socketIO(server);

// Database Connection
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("MongoDB Connected to VAMPtalk DB"))
    .catch(err => console.error("MongoDB Connection Error:", err));

// Middleware
app.set("view engine", "ejs");
app.use(express.static(path.join(__dirname, "public")));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
    secret: "a_very_strong_secret_for_vamptalk_session",
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

// --- Routes (No changes here, same as before) ---
app.get("/", (req, res) => {
    if (req.session.userId) {
        res.render("index", { name: req.session.name });
    } else {
        res.redirect("/login");
    }
});
app.get("/login", (req, res) => res.render("login", { error: null }));
app.get("/register", (req, res) => res.render("register", { error: null }));
app.post("/register", async (req, res) => {
    const { name, username, password } = req.body;
    try {
        const existingUser = await User.findOne({ username });
        if (existingUser) return res.render("register", { error: "Username already exists!" });
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ name, username, password: hashedPassword });
        await user.save();
        req.session.userId = user._id;
        req.session.name = user.name;
        res.redirect("/");
    } catch (err) {
        res.render("register", { error: "Something went wrong." });
    }
});
app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user || !await bcrypt.compare(password, user.password)) {
            return res.render("login", { error: "Invalid username or password." });
        }
        req.session.userId = user._id;
        req.session.name = user.name;
        res.redirect("/");
    } catch (err) {
        res.render("login", { error: "An error occurred." });
    }
});
app.get("/logout", (req, res) => {
    req.session.destroy(() => res.redirect("/login"));
});
app.get("/create-room", (req, res) => {
    if (!req.session.userId) return res.redirect('/login');
    const roomID = Math.random().toString(36).substr(2, 9);
    res.redirect(`/room/${roomID}`);
});
app.get("/room/:roomID", (req, res) => {
    res.render("room", {
        roomID: req.params.roomID,
        isLoggedIn: !!req.session.userId,
        name: req.session.name || null,
        appUrl: `https://${req.headers.host}`
    });
});

// --- Socket.IO Logic (Updated) ---
io.on("connection", (socket) => {
    socket.on("join-room", (roomID, peerID, displayName) => {
        const room = io.sockets.adapter.rooms.get(roomID);
        const numClients = room ? room.size : 0;

        if (numClients >= 2) {
            socket.emit('room-full');
            return;
        }

        socket.join(roomID);
        socket.to(roomID).emit("user-connected", peerID, displayName);

        socket.on('disconnect', () => {
            socket.to(roomID).emit('user-disconnected', peerID, displayName);
        });
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`🚀 VAMPtalk server is live on port ${PORT}`));