const https = require('https');
const fs = require('fs');
const path = require('path');

const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

const cors = require("cors");
const express = require("express");
const bcrypt = require("bcrypt");
const { connectMongoose } = require("./connect");
const User = require("./models/User");
const Message = require("./models/Message");

const app = express();
const port = process.env.PORT || 3002;

app.use(
    cors({
        // EXERCISE 4.7
        origin: "https://localhost:3000",
        credentials: true,
    })
);
app.use(express.json());
app.use(cookieParser());

//* ********************* Manage accounts **************** */

app.post("/signup", async (req, res) => {
    console.log("POST request received on signup route");
    const newUser = req.body;

    const existingUser = await User.exists(newUser.username);
    if (!existingUser) {
        bcrypt.hash(newUser.password, 10, async function (err, hash) {
            if (!(err instanceof Error)) {
                newUser.password = hash;

                const results = await User.signup(newUser);
                console.log(`New user created with id: ${results._id}`);

                const token = jwt.sign(
                    { username: newUser.username },
                    process.env.JWT_SECRET,
                    { expiresIn: "7d" }
                );
                res.cookie("token", token, {
                    httpOnly: true,
                    sameSite: "None",
                    secure: true,
                });

                res.sendStatus(201);
            } else {
                res.sendStatus(500);
            }
        });
    } else {
        res.sendStatus(400);
    }
});

app.post("/login", async (req, res) => {
    console.log("POST request received on login route");
    const user = req.body;

    const existingUser = await User.findOne({ username: user.username }).exec();
    if (existingUser !== null) {
        bcrypt.compare(
            user.password,
            existingUser.password,
            function (err, result) {
                if (!(err instanceof Error) && result) {
                    const token = jwt.sign(
                        { username: user.username },
                        process.env.JWT_SECRET,
                        { expiresIn: "7d" }
                    );
                    res.cookie("token", token, {
                        httpOnly: true,
                        sameSite: "None",
                        secure: true,
                    });

                    res.sendStatus(200);
                } else {
                    res.sendStatus(401);
                }
            }
        );
    } else {
        res.sendStatus(401);
    }
});

app.post("/logout", (req, res) => {
    res.clearCookie("token", {
        httpOnly: true,
        sameSite: "None",
        secure: true,
    });
    res.sendStatus(200);
});

//* ********************* Middleware authorizers **************** */

async function requireValidTokenIfSecret(req, res, next) {
    if (req.params.secret === "true") {
        const token = req.cookies.token;
        if (!token) {
            res.status(403).json([]); // Forbidden if no token is found
        }
        jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
            if (err) {
                res.status(403).json([]); // Forbidden if token is invalid
            }
        });
    }

    if (res.statusCode !== 403) {
        next();
    }
}

async function requireMatchingUserOrNoUser(req, res, next) {
    const token = req.cookies.token;
    if (token) {
        jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
            if (err || decoded.username !== req.body.user) {
                res.status(403).json([]); // Forbidden if token is invalid
            }
        });
    } else {
        const userExists = await User.exists(req.body.user);
        if (userExists) {
            res.status(403).json([]); // Forbidden if user exists and token not provided
        }
    }

    if (res.statusCode !== 403) {
        next();
    }
}

async function requireMatchingAuthorOrNoUser(req, res, next) {
    const message = await Message.get(req.params.id);
    if (message) {
        const token = req.cookies.token;
        if (token) {
            jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
                if (err || decoded.username !== message.user) {
                    res.status(403).json([]); // Forbidden if token is invalid
                }
            });
        } else {
            const userExists = await User.exists(message.user);
            if (userExists) {
                res.status(403).json([]); // Forbidden if user exists and token not provided
            }
        }
    }

    if (res.statusCode !== 403) {
        next();
    }
}


//* ********************* Manage messages **************** */

// Home dynamic route to get public or secret messages
app.get("/:secret", requireValidTokenIfSecret, async (req, res) => {
    const results = await Message.readAll(req.params.secret);
    res.send(results);

    console.log("GET request received on home page");
});

// Post route to post a new message
app.post("/message", requireMatchingUserOrNoUser, async (req, res) => {
    const newMessage = req.body;
    const results = await Message.createNew(newMessage);
    res.sendStatus(201);

    console.log("POST request received on message route");
    console.log(`New message created with id: ${results._id}`);
});

// Update route to update an existing message
app.patch("/message/:id", requireMatchingAuthorOrNoUser, async (req, res) => {
    const messageUpdate = req.body;
    const results = await Message.update(req.params.id, messageUpdate);

    res.sendStatus(200);

    console.log("PATCH request received on message route");
    console.log(`Message with id ${req.params.id} updated`);
});

// Delete route to delete an existing message
app.delete("/message/:id", requireMatchingAuthorOrNoUser, async (req, res) => {
    const results = await Message.delete(req.params.id);
    res.sendStatus(200);

    console.log("DELETE request received on message route");
    console.log(`Message with id ${req.params.id} deleted`);
});

//* ********************* Launching the server **************** */

const start = async () => {
    try {
        await connectMongoose();

        // EXERCISES 4.4 - 4.6
        // app.listen(port, () => console.log(`Server running on port ${port}...`));

        const httpsOptions = {
            key: fs.readFileSync(path.resolve(__dirname, '../localhost-key.pem')),
            cert: fs.readFileSync(path.resolve(__dirname, '../localhost.pem'))
        };
        https.createServer(httpsOptions, app).listen(port, () => {
            console.log(`Express API server running on https://localhost:${port}`);
        });
    }
    catch (err) {
        console.error(err);
    }
};

start();
