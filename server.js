require('dotenv').config(); // Memuat variabel lingkungan dari .env
const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const MySQLStore = require("express-mysql-session")(session);
const { body, validationResult } = require("express-validator");

// Tambahan modul untuk file upload
const multer = require("multer");
const fs = require("fs");
const path = require("path");

const app = express();

// Gunakan Helmet untuk mengamankan header HTTP
app.use(helmet());

// Konfigurasi CORS (pastikan CLIENT_URL didefinisikan di environment)
app.use(
  cors({
    origin: process.env.CLIENT_URL || "http://localhost:5173",
    credentials: true,
  })
);

// Parsing JSON dan cookie
app.use(express.json());
app.use(cookieParser());

// Buat connection pool dengan kredensial dari environment
const pool = mysql.createPool({
  host: process.env.DB_HOST || "sq21z.h.filess.io",
  user: process.env.DB_USER || "myapp_worthbuyam",
  port: process.env.DB_PORT || "3307",
  password: process.env.DB_PASSWORD || "3d8d4b4dbc719587f9089f082d29c1d9a464097f",
  database: process.env.DB_NAME || "myapp_worthbuyam",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// Verifikasi koneksi database
pool.getConnection((err, connection) => {
  if (err) {
    console.error("Database connection failed:", err);
  } else {
    console.log("Connected to MySQL database!");
    connection.release();
  }
});

// Buat session store menggunakan MySQL
const sessionStore = new MySQLStore({}, pool.promise());

// Konfigurasi sesi
app.use(
  session({
    secret: process.env.SESSION_SECRET || "your_secret_key_here", // Gunakan secret yang kuat dan simpan di environment
    resave: false,
    saveUninitialized: false,
    store: sessionStore, // Menggunakan MySQL session store
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // Hanya true bila menggunakan HTTPS di produksi
      sameSite: process.env.NODE_ENV === "production" ? "strict" : "lax",
      maxAge: 24 * 60 * 60 * 1000, // 1 hari
    },
  })
);

// Rate limiter untuk endpoint autentikasi guna mencegah brute force
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 menit
  max: 100, // Batas maksimal 100 request per IP dalam window ini
  message: "Terlalu banyak permintaan dari IP ini, silakan coba lagi nanti.",
});

// Terapkan rate limiter pada endpoint login, register, dan forgot-password
app.use(["/login", "/register", "/forgot-password"], authLimiter);

// Fungsi utilitas untuk menangani error query
function handleQueryError(err, res, defaultMessage) {
  console.error(defaultMessage, err);
  // Untuk produksi, hindari menampilkan detail error
  const message =
    process.env.NODE_ENV === "production"
      ? defaultMessage
      : `${defaultMessage}: ${err.message}`;
  return res.status(500).json({ success: false, message });
}

// ----------------------
// Endpoint API
// ----------------------

app.get("/", (req, res) => {
  res.send("Selamat datang di API Worthbuyam Ver art");
});

// API LOGIN: Autentikasi pengguna dan simpan data sesi
app.post(
  "/login",
  [
    body("email").isEmail().withMessage("Email tidak valid"),
    body("password").notEmpty().withMessage("Password diperlukan"),
  ],
  async (req, res) => {
    // Cek validasi input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res
        .status(400)
        .json({ success: false, errors: errors.array() });
    }

    const { email, password } = req.body;

    pool.query(
      "SELECT * FROM users WHERE email = ?",
      [email],
      async (err, results) => {
        if (err) {
          return handleQueryError(err, res, "Error saat login");
        }

        if (results.length === 0) {
          return res
            .status(401)
            .json({ success: false, message: "User dengan email tersebut tidak ditemukan" });
        }

        const user = results[0];
        try {
          const isPasswordValid = await bcrypt.compare(password, user.password);
          if (!isPasswordValid) {
            return res
              .status(401)
              .json({ success: false, message: "Password tidak valid" });
          }
        } catch (error) {
          return handleQueryError(error, res, "Error saat membandingkan password");
        }

        // Simpan data pengguna di sesi
        req.session.user = { id: user.id, name: user.name, email: user.email };
        return res.json({
          success: true,
          message: "Login berhasil",
          user: req.session.user,
        });
      }
    );
  }
);

// API LOGOUT: Hapus sesi pengguna dan cookie
app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Error saat logout:", err);
      return res
        .status(500)
        .json({ success: false, message: "Logout gagal" });
    }
    res.clearCookie("connect.sid");
    return res.json({ success: true, message: "Logout berhasil" });
  });
});

// API CEK STATUS LOGIN: Periksa apakah pengguna sudah terautentikasi
app.get("/auth", (req, res) => {
  if (req.session.user) {
    return res.json({ isAuthenticated: true, user: req.session.user });
  }
  return res.json({ isAuthenticated: false });
});

// API REGISTER: Daftarkan pengguna baru dengan validasi input
app.post(
  "/register",
  [
    body("name").notEmpty().withMessage("Nama diperlukan"),
    body("email").isEmail().withMessage("Email tidak valid"),
    body("password")
      .isLength({ min: 6 })
      .withMessage("Password harus minimal 6 karakter"),
  ],
  async (req, res) => {
    // Cek validasi input
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res
        .status(400)
        .json({ success: false, errors: errors.array() });
    }

    const { name, email, password } = req.body;

    pool.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) => {
      if (err) {
        return handleQueryError(err, res, "Error saat pengecekan user");
      }
      if (results.length > 0) {
        return res
          .status(409)
          .json({ success: false, message: "Email sudah digunakan" });
      }

      try {
        const hashedPassword = await bcrypt.hash(password, 10);
        pool.query(
          "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
          [name, email, hashedPassword],
          (err, result) => {
            if (err) {
              if (err.code === "ER_DUP_ENTRY") {
                return res
                  .status(409)
                  .json({ success: false, message: "Email sudah digunakan" });
              }
              return handleQueryError(err, res, "Error saat registrasi");
            }
            return res.json({
              success: true,
              message: "Registrasi berhasil",
            });
          }
        );
      } catch (error) {
        console.error("Error saat hashing password:", error);
        return res
          .status(500)
          .json({ success: false, message: "Internal server error" });
      }
    });
  }
);

// API FORGOT PASSWORD: Proses permintaan reset password
app.post(
  "/forgot-password",
  [body("email").isEmail().withMessage("Email tidak valid")],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res
        .status(400)
        .json({ success: false, errors: errors.array() });
    }

    const { email } = req.body;

    pool.query("SELECT * FROM users WHERE email = ?", [email], (err, results) => {
      if (err) {
        return handleQueryError(err, res, "Error saat request reset password");
      }
      if (results.length === 0) {
        return res
          .status(404)
          .json({ success: false, message: "User dengan email tersebut tidak ditemukan" });
      }

      // Pada implementasi nyata:
      // 1. Buat token reset password.
      // 2. Simpan token dengan masa berlaku ke database.
      // 3. Kirim email ke pengguna berisi link reset password.
      // Untuk demo, kembalikan pesan sukses:
      return res.json({
        success: true,
        message: "Instruksi reset password telah dikirim ke email Anda.",
      });
    });
  }
);

// ----------------------
// CRUD Endpoint untuk Art
// ----------------------

// Pastikan folder uploads/Art ada
const uploadDir = path.join(__dirname, "uploads/Art");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Konfigurasi multer untuk upload file
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});
const upload = multer({ storage: storage });

// CREATE (Tambah data Art)
// Endpoint: POST /art
// Field image dikirim dengan key "image"
app.post("/art", upload.single("image"), (req, res) => {
  const { title, description } = req.body;
  const imageUrl = req.file ? `/uploads/Art/${req.file.filename}` : null;

  pool.query(
    "INSERT INTO Art (title, description, image_url) VALUES (?, ?, ?)",
    [title, description, imageUrl],
    (err, result) => {
      if (err) return res.status(500).json({ success: false, message: err.message });
      res.json({ success: true, message: "Data Art berhasil ditambahkan", id: result.insertId });
    }
  );
});

// READ (Ambil semua data Art)
// Endpoint: GET /art
app.get("/art", (req, res) => {
  pool.query("SELECT * FROM Art", (err, results) => {
    if (err) return res.status(500).json({ success: false, message: err.message });
    res.json({ success: true, data: results });
  });
});

// READ by ID (Ambil satu data Art berdasarkan ID)
// Endpoint: GET /art/:id
app.get("/art/:id", (req, res) => {
  const { id } = req.params;
  pool.query("SELECT * FROM Art WHERE id = ?", [id], (err, result) => {
    if (err) return res.status(500).json({ success: false, message: err.message });
    if (result.length === 0) return res.status(404).json({ success: false, message: "Data tidak ditemukan" });
    res.json({ success: true, data: result[0] });
  });
});

// UPDATE (Edit data Art)
// Endpoint: PUT /art/:id
// Jika ada file baru, akan menggantikan image_url sebelumnya.
app.put("/art/:id", upload.single("image"), (req, res) => {
  const { id } = req.params;
  const { title, description } = req.body;
  const imageUrl = req.file ? `/uploads/Art/${req.file.filename}` : null;

  let query = "UPDATE Art SET title = ?, description = ?";
  let params = [title, description];

  if (imageUrl) {
    query += ", image_url = ?";
    params.push(imageUrl);
  }

  query += " WHERE id = ?";
  params.push(id);

  pool.query(query, params, (err, result) => {
    if (err) return res.status(500).json({ success: false, message: err.message });
    res.json({ success: true, message: "Data Art berhasil diperbarui" });
  });
});

// DELETE (Hapus data Art)
// Endpoint: DELETE /art/:id
// Juga menghapus file gambar yang tersimpan (jika ada)
app.delete("/art/:id", (req, res) => {
  const { id } = req.params;

  // Ambil nama file dulu untuk menghapus dari folder
  pool.query("SELECT image_url FROM Art WHERE id = ?", [id], (err, result) => {
    if (err) return res.status(500).json({ success: false, message: err.message });
    if (result.length === 0) return res.status(404).json({ success: false, message: "Data tidak ditemukan" });

    const imageUrl = result[0].image_url;
    if (imageUrl) {
      const filePath = path.join(__dirname, imageUrl);
      fs.unlink(filePath, (err) => {
        if (err && err.code !== "ENOENT") console.error("Gagal menghapus file:", err);
      });
    }

    // Hapus data dari database
    pool.query("DELETE FROM Art WHERE id = ?", [id], (err, result) => {
      if (err) return res.status(500).json({ success: false, message: err.message });
      res.json({ success: true, message: "Data Art berhasil dihapus" });
    });
  });
});

// ----------------------
// Menjalankan Server
// ----------------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server berjalan di port ${PORT}`);
});
