
const { onRequest } = require("firebase-functions/v2/https");
const { defineSecret } = require("firebase-functions/params");
const { initializeApp } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");

initializeApp();

const loginUsers = defineSecret("LOGIN_USERS");

const allowedUsers = [
  "enes",
  "robert",
  "oliver",
  "tim",
  "felix",
  "david",
  "simon",
  "axel",
  "sebastian"
];

exports.login = onRequest(
  { secrets: [loginUsers], maxInstances: 2 },
  async (req, res) => {
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.set("Access-Control-Allow-Headers", "Content-Type");

    if (req.method === "OPTIONS") {
      return res.status(204).send("");
    }

    if (req.method !== "POST") {
      return res.status(405).json({ error: "Methode nicht erlaubt." });
    }

    try {
      const { username, password } = req.body || {};
      const user = String(username || "").trim().toLowerCase();

      if (
        !allowedUsers.includes(user) ||
        typeof password !== "string" ||
        password.length < 1 ||
        password.length > 200
      ) {
        return res.status(401).json({
          error: "Benutzername oder Passwort falsch."
        });
      }

      const users = JSON.parse(loginUsers.value());
      const expectedPassword = users[user];

      if (
        typeof expectedPassword !== "string" ||
        password !== expectedPassword
      ) {
        return res.status(401).json({
          error: "Benutzername oder Passwort falsch."
        });
      }

      const customToken = await getAuth().createCustomToken(user);

      return res.status(200).json({ customToken });
    } catch (error) {
      console.error("Login fehlgeschlagen:", error);
      return res.status(500).json({
        error: "Anmeldung momentan nicht möglich."
      });
    }
  }
);
