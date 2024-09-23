const express = require("express");
const app = express();
app.use(express.json());
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const { Pool } = require("pg");
const multer = require('multer');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const util = require('util');
const session = require("express-session");

// Database connection
const pool = new Pool({
  host: "localhost",
  user: "postgres",
  password: process.env.DB_PASSWORD,
  port: 5432,
  database: "share2teach"
});
// Initialize session middleware
app.use(session({
  secret: process.env.SESSION_SECRET,  // Use a secure secret key from environment variables
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: process.env.NODE_ENV === 'production',  // Set to true in production to enforce HTTPS
    maxAge: 24 * 60 * 60 * 1000  // 1 day in milliseconds
  }
}));
// Middleware to validate input
function validInfo(req, res, next) {
  const { email, password } = req.body;
  function validEmail(userEmail) {
    return /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/.test(userEmail);
  }

  if (req.path === "/register") {
    const { Fname, Lname } = req.body;
    if (![email, Fname, Lname, password].every(Boolean)) {
      return res.status(400).json({ msg: "incomplete registration details" });
    } else if (!validEmail(email)) {
      return res.status(400).json({ msg: "Invalid Email" });
    }
  } else if (req.path === "/login") {
    if (![email, password].every(Boolean)) {
      return res.status(400).json({ msg: "incomplete login details" });
    } else if (!validEmail(email)) {
      return res.status(400).json({ msg: "Invalid Email" });
    }
  }
  next();
}

// JWT generation function
function jwtGenerator(user_id, token_version) {
  const payload = {
    user: { id: user_id, token_version }
  };
  return jwt.sign(payload, process.env.jwtSecret, { expiresIn: "1h" });
}

// Authorization middleware
function authorize(req, res, next) {
  const token = req.header("jwt_token");
  if (!token) {
    return res.status(403).json({ msg: "Authorization denied" });
  }

  try {
    const verify = jwt.verify(token, process.env.jwtSecret);
    req.user = verify.user;

    // Check if token_version matches the current version in the database
    pool.query("SELECT token_version FROM public.\"USER\" WHERE user_id = $1", [req.user.id], (err, result) => {
      if (err) {
        return res.status(500).json({ msg: "Server error" });
      }

      if (result.rows.length === 0) {
        return res.status(401).json({ msg: "User not found" });
      }

      const currentTokenVersion = result.rows[0].token_version;
      if (currentTokenVersion !== req.user.token_version) {
        return res.status(401).json({ msg: "Token is invalid due to version mismatch" });
      }

      next();
    });
  } catch (err) {
    console.error(err.message);
    res.status(401).json({ msg: "Token is not valid" });
  }
}
// Root route
app.get("/", (req, res) => {
  res.send("Server is now running");
});


// Registration route
app.post("/register", validInfo, async (req, res) => {
  const { email, Fname, Lname, password } = req.body;
  const role = 'open-access'; // Set default role for new users
  try {
    const user = await pool.query("SELECT * FROM public.\"USER\" WHERE user_email = $1", [email]);
    if (user.rows.length > 0) {
      return res.status(401).json({ msg: "User already exists" });
    }

    const salt = await bcrypt.genSalt(10);
    const bcryptPassword = await bcrypt.hash(password, salt);

    const newUser = await pool.query(
      'INSERT INTO public."USER" (user_Fname, user_Lname, user_email, userpassword, role) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [Fname, Lname, email, bcryptPassword, role]
    );

    const jwtToken = jwtGenerator(newUser.rows[0].user_id, 0);  // Pass token_version = 0

    return res.json({ jwtToken });
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
});


// Login route
app.post("/login", validInfo, async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await pool.query("SELECT * FROM public.\"USER\" WHERE user_email = $1", [email]);
    if (user.rows.length === 0) {
      return res.status(401).json({ msg: "Invalid Credentials" });
    }
    const validPassword = await bcrypt.compare(password, user.rows[0].userpassword);
    if (!validPassword) {
      return res.status(401).json({ msg: "Invalid Credentials" });
    }
    
    const jwtToken = jwtGenerator(user.rows[0].user_id, user.rows[0].token_version);
    return res.json({ jwtToken });
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
});

// Logout route
app.post("/logout", authorize, async (req, res) => {
  try {
    // Increment the token_version to invalidate the current token
    await pool.query("UPDATE public.\"USER\" SET token_version = token_version + 1 WHERE user_id = $1", [req.user.id]);

    req.session.destroy((err) => {
      if (err) {
        return res.status(500).json({ msg: "Error logging out" });
      }
      return res.json({ msg: "Successfully logged out. Token is now invalid." });
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
});
// Dashboard route (fetch user info)
app.post("/dashboard", authorize, async (req, res) => {
  try {
    const user = await pool.query("SELECT user_Fname, user_Lname FROM public.\"USER\" WHERE user_id = $1", [req.user.id]);
    res.json(user.rows[0]);
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
});

// File management routes
app.get("/search/files", async (req, res) => {
  try {
    const { file_name, subject, grade, keywords, tags } = req.query; // Retrieve search criteria from query parameters

    let searchQuery = "SELECT * FROM public.\"FILE\" WHERE 1 = 1";  // Initialize query with a true condition
    const values = [];

    // Search by file_name if provided
    if (file_name) {
      searchQuery += ` AND file_name ILIKE $${values.length + 1}`;
      values.push(`%${file_name}%`);
    }

    // Search by subject if provided
    if (subject) {
      searchQuery += ` AND subject ILIKE $${values.length + 1}`;
      values.push(`%${subject}%`);
    }

    // Search by grade if provided
    if (grade) {
      searchQuery += ` AND grade ILIKE $${values.length + 1}`;
      values.push(`%${grade}%`);
    }

    // Search by keywords if provided (checks for overlap between arrays)
    if (keywords) {
      const keywordsArray = keywords.split(",");  // Split keywords into an array
      searchQuery += ` AND keywords && $${values.length + 1}`;
      values.push(keywordsArray);
    }

    // Search by tags if provided (checks for overlap between arrays)
    if (tags) {
      const tagsArray = tags.split(",");  // Split tags into an array
      searchQuery += ` AND tags && $${values.length + 1}`;
      values.push(tagsArray);
    }

    const results = await pool.query(searchQuery, values);  // Execute the query with values
    res.json(results.rows);  // Return the search results as JSON
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
});



// Set up security middleware
app.use(helmet());
app.use(morgan('combined'));

// Rate limiter
const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many upload attempts from this IP, please try again later."
});

// Multer setup
const storage = multer.diskStorage({
  destination: process.env.UPLOAD_DIR || './uploads/',
  filename: function (req, file, cb) {
    const sanitizedFilename = file.fieldname + '-' + Date.now() + path.extname(file.originalname);
    cb(null, sanitizedFilename);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 20 * 1024 * 1024 },
  fileFilter: function (req, file, cb) {
    const filetypes = /pdf|doc|docx|xls|xlsx|ppt|pptx|txt/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = filetypes.test(file.mimetype);
    if (mimetype && extname) { cb(null, true); }
    else { cb("Error: Documents Only!"); }
  }
}).single('document');

const uploadAsync = util.promisify(upload);

// File upload route
app.post('/upload', uploadLimiter, authorize, async (req, res) => {
  try {
    await uploadAsync(req, res);

    if (!req.file) {
      return res.status(400).send({ message: 'No file selected!' });
    }

    const { subject, grade, keywords, tags } = req.body;
    const file_name = req.file.originalname;
    const storage_path = `${process.env.UPLOAD_DIR || './uploads/'}${req.file.filename}`;
    const uploaded_by = req.user.id;
    const rating = null;

    console.log('File Details:', {
      file_name,
      subject,
      grade,
      keywords: keywords ? keywords.split(",") : null,
      tags: tags ? tags.split(",") : null,
      rating,
      storage_path,
      uploaded_by
    });

    // Insert the uploaded file details into the FILE table
    const newFile = await pool.query(
      `INSERT INTO public."FILE" (file_name, subject, grade, keywords, tags, rating, storage_path, uploaded_by, upload_date)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CURRENT_TIMESTAMP)
       RETURNING *`,
      [file_name, subject, grade, keywords ? keywords.split(",") : null, tags ? tags.split(",") : null, rating, storage_path, uploaded_by]
    );

    // Return a response with file details
    res.status(200).json({
      message: 'Document uploaded and details added to the database!',
      file: newFile.rows[0]
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).send({ message: 'Server error' });
  }
});

// Moderate document
app.post("/moderate-document", authorize, async (req, res) => {
  const { file_id, action, comments } = req.body;
  const moderator_id = req.user.id;
  if (!['approved', 'rejected'].includes(action)) {
    return res.status(400).json({ msg: "Invalid action" });
  }
  try {
    await pool.query(
      `INSERT INTO public."MODERATION_HISTORY" (file_id, moderator_id, action, comments) VALUES ($1, $2, $3, $4)`,
      [file_id, moderator_id, action, comments]
    );
    await pool.query(
      `UPDATE "FILE" SET status = $1 WHERE file_id = $2`,
      [action, file_id]
    );
    res.status(200).json({ msg: "Document moderated successfully" });
  } catch (err) {
    res.status(500).send("Server error");
  }
});

// Route to rate a file
app.post("/rate", async (req, res) => {
  const { file_id, rating } = req.body;

  // Check if the request is authenticated with JWT
  const token = req.header("jwt_token");
  let user_id = null;

  if (token) {
    try {
      const verify = jwt.verify(token, process.env.jwtSecret);
      user_id = verify.user.id;
    } catch (err) {
      return res.status(401).json({ msg: "Token is not valid" });
    }
  }

  // Validate input
  if (!file_id || !rating) {
    return res.status(400).json({ msg: "Please provide a file_id and rating" });
  }

  if (rating < 1 || rating > 5) {
    return res.status(400).json({ msg: "Rating must be between 1 and 5" });
  }

  try {
    // Check if the file exists
    const fileExists = await pool.query("SELECT * FROM public.\"FILE\" WHERE file_id = $1", [file_id]);
    if (fileExists.rows.length === 0) {
      return res.status(404).json({ msg: "File not found" });
    }

    if (user_id) {
      // Authenticated user: Store rating by user_id
      const existingRating = await pool.query(
        "SELECT * FROM public.\"RATING\" WHERE file_id = $1 AND user_id = $2",
        [file_id, user_id]
      );

      if (existingRating.rows.length > 0) {
        await pool.query(
          'UPDATE public."RATING" SET rating = $1 WHERE file_id = $2 AND user_id = $3',
          [rating, file_id, user_id]
        );
      } else {
        await pool.query(
          'INSERT INTO public."RATING" (file_id, user_id, rating) VALUES ($1, $2, $3)',
          [file_id, user_id, rating]
        );
      }
    } else {
      // Open Access User: Store rating by session ID
      const sessionId = req.sessionID; 

      const existingRating = await pool.query(
        "SELECT * FROM public.\"RATING\" WHERE file_id = $1 AND session_id = $2",
        [file_id, sessionId]
      );

      if (existingRating.rows.length > 0) {
        await pool.query(
          'UPDATE public."RATING" SET rating = $1 WHERE file_id = $2 AND session_id = $3',
          [rating, file_id, sessionId]
        );
      } else {
        await pool.query(
          'INSERT INTO public."RATING" (file_id, session_id, rating) VALUES ($1, $2, $3)',
          [file_id, sessionId, rating]
        );
      }
    }

    // Calculate the new average rating for the file
    const newAverageRating = await pool.query(
      'SELECT AVG(rating) AS avg_rating FROM public."RATING" WHERE file_id = $1',
      [file_id]
    );

    const averageRating = parseFloat(newAverageRating.rows[0].avg_rating).toFixed(1);

    // Update the file's average rating
    await pool.query(
      'UPDATE public."FILE" SET rating = $1 WHERE file_id = $2',
      [averageRating, file_id]
    );

    res.status(200).json({ msg: "Rating submitted successfully", averageRating });
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
});

// Route to add a new FAQ question (Open Access or Authenticated users)
app.post("/faq", async (req, res) => {
  const { question } = req.body;
  const token = req.header("jwt_token");
  let user_id = null;

  if (token) {
    try {
      const verify = jwt.verify(token, process.env.jwtSecret);
      user_id = verify.user.id;
    } catch (err) {
      return res.status(401).json({ msg: "Token is not valid" });
    }
  }

  if (!question) {
    return res.status(400).json({ msg: "Please provide a question" });
  }

  try {
    await pool.query(
      'INSERT INTO public."FAQ" (question, created_by) VALUES ($1, $2) RETURNING *',
      [question, user_id]
    );
    res.status(200).json({ msg: "Question submitted successfully" });
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
});

// Route to answer a question (Admins or Educators)
app.post("/faq/answer", authorize, async (req, res) => {
  const { faq_id, answer } = req.body;

  // Check if the user is an Admin or Educator
  const userRole = await pool.query('SELECT role FROM public.\"USER\" WHERE user_id = $1', [req.user.id]);
  if (!['admin', 'educator'].includes(userRole.rows[0].role)) {
    return res.status(403).json({ msg: "Permission denied" });
  }

  if (!faq_id || !answer) {
    return res.status(400).json({ msg: "Please provide both FAQ ID and answer" });
  }

  try {
      await pool.query(
        "UPDATE public.\"FAQ\" SET answer = $1, status = 'answered' WHERE faq_id = $2",
        [answer, faq_id]
      );
    res.status(200).json({ msg: "Answer added successfully" });
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
});

// Route to fetch all answered FAQs
app.get("/faqs", async (req, res) => {
  try {
    const faqs = await pool.query("SELECT * FROM public.\"FAQ\" WHERE status = 'answered' ORDER BY created_at DESC");
    res.status(200).json(faqs.rows);
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
});

// Route to search FAQs by a question 
app.post("/faqs/search", async (req, res) => {
  const { search_query } = req.body;
  if (!search_query) {
    return res.status(400).json({ msg: "Please provide a search query" });
  }

  try {
    const searchResult = await pool.query(
      "SELECT * FROM public.\"FAQ\" WHERE question ILIKE $1 AND status = 'answered'",
      [`%${search_query}%`]
    );
    res.status(200).json(searchResult.rows);
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server error");
  }
});

// Start server
app.listen(3000, () => {
  console.log("Server is running on port 3000");
});