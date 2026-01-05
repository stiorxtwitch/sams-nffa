import express from "express"
import pkg from "pg"
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"
import cors from "cors"

const { Pool } = pkg
const app = express()

app.use(cors())
app.use(express.json())
app.use(express.static("public"))

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
})

const JWT_SECRET = "CHANGE_MOI"

// ==========================
// LOGIN
// ==========================
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body

  const { rows } = await pool.query(
    "SELECT id, username, password_hash, permission FROM users WHERE username=$1",
    [username]
  )

  if (!rows.length)
    return res.status(401).json({ error: "Utilisateur inconnu" })

  const user = rows[0]
  const ok = await bcrypt.compare(password, user.password_hash)
  if (!ok)
    return res.status(401).json({ error: "Mot de passe incorrect" })

  await pool.query(
    "UPDATE users SET presence=TRUE WHERE id=$1",
    [user.id]
  )

  const token = jwt.sign(
    { id: user.id, username: user.username, permission: user.permission },
    JWT_SECRET,
    { expiresIn: "8h" }
  )

  res.json({ token, user: { id: user.id, username: user.username, permission: user.permission } })
})

// ==========================
// LOGOUT
// ==========================
app.post("/api/logout", async (req, res) => {
  const { userId } = req.body
  await pool.query(
    "UPDATE users SET presence=FALSE WHERE id=$1",
    [userId]
  )
  res.json({ ok: true })
})

// ==========================
// AUTO OFFLINE (crash serveur)
// ==========================
process.on("SIGINT", async () => {
  await pool.query("UPDATE users SET presence=FALSE")
  process.exit()
})

app.listen(3000, () =>
  console.log("✅ Backend prêt → http://localhost:3000")
)
