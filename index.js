// require("dotenv").config();
// const jsonServer = require("json-server");
// const express = require("express");
// const cors = require("cors");
// const PORT = process.env.PORT || 4001;
// const app = express();
// const corsOptions = {
//   origin: "*",
//   methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
//   credentials: true,
//   allowedHeaders: "*",
//   // allowedHeaders: "Content-Type,Authorization",
//   maxAge: -1,
// };
// app.use(cors(corsOptions));
// // app.options("*", cors(corsOptions));
// app.use(express.json());
// app.use("/api", jsonServer.defaults(), jsonServer.router("db.json"));

require("dotenv").config();
const express = require("express");
const fs = require("fs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jsonServer = require("json-server");
const verifyToken = require("./middleware/auth");

const app = express();
app.use(express.json());
const corsOptions = {
  origin: "*",
  methods: "GET,HEAD,PUT,PATCH,POST,DELETE",
  credentials: true,
  allowedHeaders: "*",
  // allowedHeaders: "Content-Type,Authorization",
  maxAge: -1,
};
app.use(cors(corsOptions));
// app.options("*", cors(corsOptions));

let rawdata = fs.readFileSync("db.json");
let database = JSON.parse(rawdata);
let users = database.users;

const generateTokens = (payload) => {
  const { id, email } = payload;
  const accessToken = jwt.sign({ id, email }, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "5m",
  });
  const refreshToken = jwt.sign(
    { id, email },
    process.env.REFRESH_TOKEN_SECRET,
    {
      expiresIn: "24h",
    }
  );

  return { accessToken, refreshToken };
};

function updateRefreshToken(email, refreshToken) {
  users = users.map((user) => {
    if (user.email === email) {
      return {
        ...user,
        refreshToken,
      };
    }
    return user;
  });
  fs.writeFileSync("db.json", JSON.stringify({ ...database, users }));
}

app.post("/auth/login", (req, res) => {
  const email = req.body.email;
  const user = users.find((user) => user.email === email);
  if (!user) return res.sendStatus(401);
  const dbPassword = user.password;
  bcrypt.compare(req.body.password, dbPassword, (err, hash) => {
    if (err || !hash) {
      return res.status(403).json({
        statusCode: 403,
        error: { message: "Password does not match" },
      });
    }
    const tokens = generateTokens(user);
    updateRefreshToken(user.email, tokens.refreshToken);
    res.json(tokens);
  });
});

app.post("/token", (req, res) => {
  const refreshToken = req.body.refreshToken;
  if (!refreshToken) return res.sendStatus(401);
  const user = users.find((user) => user.refreshToken === refreshToken);
  if (!user) return res.sendStatus(403);
  try {
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    const tokens = generateTokens(user);
    updateRefreshToken(user.email, tokens.refreshToken);
    res.json(tokens);
  } catch (err) {
    res.sendStatus(403);
  }
});

app.post("/auth/register", (req, res) => {
  const { name, password, email, permissions } = req.body;
  const user = users.find((user) => user.email === email);
  if (user) return res.sendStatus(409).json({ error: "User already exists" });
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) return;
    users.push({
      id: users.length + 1,
      name,
      password: hash,
      email,
      refreshToken: null,
      permissions,
    });
    fs.writeFileSync("db.json", JSON.stringify({ ...database, users }));
    res.sendStatus(201);
  });
});

app.delete("/logout", verifyToken, (req, res) => {
  const user = users.find((user) => user.id === req.userId);
  updateRefreshToken(user.email, "");
  res.sendStatus(204);
});

app.use("/api", jsonServer.defaults(), jsonServer.router("db.json"));
app.get("/api/campaigns", verifyToken, (req, res) => {
  res.json(database.campaigns);
});
app.get("/api/users", verifyToken, (req, res) => {
  res.json(database.users);
});
const HOST = "0.0.0.0";
const PORT = process.env.PORT || 4001;
app.listen(PORT, HOST, () =>
  console.log(`Server is running on http://${PORT}:${HOST}`)
);
// app.listen(PORT, () => {
//   console.log(`Server is running on port ${PORT}`);
// });
