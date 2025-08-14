import express, { json } from 'express';
import mongoose from 'mongoose';
import 'dotenv/config'
import bcrypt from 'bcrypt';
import User from './Schema/User.js';
import Blog from './Schema/Blog.js';
import { nanoid } from 'nanoid';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import admin from "firebase-admin"
import {getAuth} from "firebase-admin/auth"
import fs from 'fs';

// Firebase admin configuration - fallback to service account file if env vars not available
let serviceAccountKey;

if (process.env.FIREBASE_PROJECT_ID) {
  // Use environment variables (preferred for production)
  serviceAccountKey = {
    type: "service_account",
    project_id: process.env.FIREBASE_PROJECT_ID,
    private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
    private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
    client_email: process.env.FIREBASE_CLIENT_EMAIL,
    client_id: process.env.FIREBASE_CLIENT_ID,
    auth_uri: "https://accounts.google.com/o/oauth2/auth",
    token_uri: "https://oauth2.googleapis.com/token",
    auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs"
  };
  console.log("Using environment variables for Firebase configuration");
} else {
  // Fallback to service account file (for local development)
  try {
    const serviceAccountData = fs.readFileSync('./service-account.json', 'utf8');
    serviceAccountKey = JSON.parse(serviceAccountData);
    console.log("Using service account file for Firebase configuration");
  } catch (error) {
    console.error("No Firebase configuration found. Please set environment variables or provide service-account.json");
    console.error("Error:", error.message);
    process.exit(1);
  }
}
import aws from "aws-sdk";


const server = express();
let PORT = 3000;

// Initialize Firebase Admin with error handling
try {
  if (serviceAccountKey && serviceAccountKey.project_id) {
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccountKey)
    });
    console.log("Firebase Admin initialized successfully");
  } else {
    console.error("Firebase service account key is invalid or missing");
    // Don't exit - let the server run for health checks
  }
} catch (error) {
  console.error("Failed to initialize Firebase Admin:", error.message);
  // Don't exit - let the server run for health checks
}

let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/; // regex for email
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/; // regex for password

server.use(express.json());

// Enhanced CORS configuration
server.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    const allowedOrigins = [
      "http://localhost:5173",
      "http://localhost:3000",
      "https://connectfrontend.llp.trizenventures.com",
      "https://connect.trizenventures.com",
      "https://localhost:5173"
    ];
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.log('CORS blocked origin:', origin);
      callback(null, true); // Allow all origins for now during debugging
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin'],
  exposedHeaders: ['Content-Length', 'X-Requested-With'],
  preflightContinue: false,
  optionsSuccessStatus: 200
}));

// Explicit OPTIONS handling for all routes
server.options('*', (req, res) => {
  console.log('OPTIONS request from origin:', req.headers.origin);
  res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.status(200).send();
});

// Middleware to log all requests and add CORS headers
server.use((req, res, next) => {
  console.log(`${req.method} ${req.path} from origin: ${req.headers.origin}`);
  
  // Ensure CORS headers are always present
  res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  
  next();
});
// mongoose.connect("mongodb://127.0.0.1:27017/mydatabase", {
//     autoIndex: true // Ensures indexing
// })
mongoose.connect("mongodb+srv://commonmail511:commonmail@reactjs-blog-website.yaqi0qq.mongodb.net/?retryWrites=true&w=majority&appName=reactjs-blog-website", {
    autoIndex : true
})
.then(() => {
    console.log("Connected to MongoDB locally (Compass) successfully!");
})
.catch((err) => {
    console.error("Error connecting to MongoDB:", err.message);
});


// setting up s3 bucket
const s3 = new aws.S3({
    region:'ap-south-1',
    accessKeyId: process.env.AWS_ACCESS_KEY,
    secretAccessKey : process.env.AWS_SECRET_ACCESS_KEY 
})

const generateUploadURL =  async () => {
    const date = new Date();
    const imageName = `${nanoid()}-${date.getTime()}.jpeg`;

    return await s3.getSignedUrlPromise('putObject', {
        Bucket : 'blogwebsite-mern',
        Key: imageName,
        Expires:1000,
        ContentType: "image/jpeg"
    })
}

const formatDatatoSend = (user) => {

    const access_token = jwt.sign({id: user._id}, process.env.SECRET_ACCESS_KEY)

    return{
        access_token,
        profile_img : user.personal_info.profile_img,
        username : user.personal_info.username,
        fullname: user.personal_info.fullname
    }
}

const generateUsername = async(email) => {
    let username = email.split("@")[0];

    let isUsernameNotUnique = await User.exists({ "personal_info.username" : username }).then((result) => result)

    isUsernameNotUnique ? username += nanoid().substring(0, 5) : "";

    return username;
}

//upload image url route
server.get('/get-upload-url', (req,res) => {
    // Check if AWS credentials are properly configured
    if (!process.env.AWS_ACCESS_KEY || process.env.AWS_ACCESS_KEY === 'your-aws-access-key-here' ||
        !process.env.AWS_SECRET_ACCESS_KEY || process.env.AWS_SECRET_ACCESS_KEY === 'your-aws-secret-access-key-here') {
        return res.status(500).json({ 
            error: "AWS credentials not configured. Please add valid AWS_ACCESS_KEY and AWS_SECRET_ACCESS_KEY to your .env file" 
        });
    }
    
    generateUploadURL().then(url => res.status(200).json({ uploadURL : url }))
    .catch(err => {
        console.log(err.message);
        return res.status(500).json({ error: err.message })
    })
})

server.post("/signup", (req, res) => {

    let { fullname, email, password } = req.body;


    if(fullname.length < 3){
        return res.status(403).json({"error" : "Fullname must be at least 3 letters long"})
    }

    if(!email.length){
        return res.status(403).json({"error" : "Enter Email" })
    }

    if(!emailRegex.test(email)){
        return res.status(403).json({"error":"Email is invalid"})
    }

    if(!passwordRegex.test(password)){
        return res.status(403).json({"error":"Password should be 6 to 20 characters long with a numeric, 1 lowercase and 1 uppercase letters "})
    }

    bcrypt.hash(password, 10, async (err, hashed_password) => {

        let username = await generateUsername(email);

        let user = new User({
            personal_info: { fullname, email, password, hashed_password, username }
        })
        
        user.save().then((u) => {
            return res.status(200).json(formatDatatoSend(u))
        })

        .catch(err => {

            if(err.code == 11000){
                return res.status(500).json({"error":"Email already exists"})
            }

            return res.status(500).json({"error" : err.message})
        })
    })

})

server.post("/signin", (req,res) => {
    let {email, password} = req.body;

    User.findOne({"personal_info.email" : email})
    .then((user) => {
        if(!user){
            return res.status(403).json({"error" : "Email not found"});
        }
        
        if(!user.google_auth){
            bcrypt.compare(password, user.personal_info.hashed_password, (err, result) => {
                
                if(err){
                    return res.status(403).json({"error":"Error occurred while login please try again"});
                }

                if(!result){
                    return res.status(403).json({"error":"Incorrect password"})
                }else{
                    return res.status(200).json(formatDatatoSend(user))
                }

            })
    
        } else{
            return res.status(403).json({"error":"Account was created using googl1. Try logging in with google"})
        }

    })
    .catch(err => {
        console.log(err.message);
        return res.status(500).json({"error":err.message})
    })
})

server.post("/google-auth", async (req, res) => {
    try {
        let { access_token } = req.body;

        console.log("Google auth request received with token:", access_token);

        if (!access_token) {
            return res.status(400).json({"error": "Access token is required"});
        }

        // Check if Firebase is properly initialized
        if (!serviceAccountKey?.project_id) {
            return res.status(500).json({"error": "Firebase authentication is not configured on the server"});
        }

        // Try to verify the token with current Firebase setup
        const decodedUser = await getAuth().verifyIdToken(access_token);
        console.log("Token verified successfully for user:", decodedUser.email);

        let { email, name, picture } = decodedUser;

        // Enhance picture quality
        if (picture) {
            picture = picture.replace("s96-c", "s384-c");
        }

        // Find existing user
        let user = await User.findOne({"personal_info.email": email})
            .select("personal_info.fullname personal_info.username personal_info.profile_img google_auth");

        if (user) {
            // User exists - check if it's a Google account
            if (!user.google_auth) {
                return res.status(403).json({
                    "error": "This email was signed up without Google. Please log in with password to access the account"
                });
            }
            console.log("Existing Google user found:", user.personal_info.username);
        } else {
            // Create new user
            console.log("Creating new user for email:", email);
            let username = await generateUsername(email);

            user = new User({
                personal_info: { 
                    fullname: name, 
                    email, 
                    profile_img: picture, 
                    username 
                },
                google_auth: true
            });

            await user.save();
            console.log("New user created successfully:", username);
        }

        return res.status(200).json(formatDatatoSend(user));

    } catch (err) {
        console.error("Google auth error:", err);
        
        if (err.code === 'auth/argument-error' || err.code === 'auth/invalid-argument') {
            return res.status(400).json({"error": "Invalid access token provided"});
        } else if (err.code === 'auth/id-token-expired') {
            return res.status(401).json({"error": "Access token has expired"});
        } else {
            return res.status(500).json({
                "error": "Failed to authenticate with Google. Please try again.",
                "details": err.message
            });
        }
    }
})

// Blog-related routes
server.post("/latest-blogs", (req, res) => {
    let { page } = req.body;
    
    let maxLimit = 5;
    
    Blog.find({ draft: false })
    .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
    .sort({ "publishedAt": -1 })
    .select("blog_id title des banner activity tags publishedAt -_id")
    .skip((page - 1) * maxLimit)
    .limit(maxLimit)
    .then(blogs => {
        return res.status(200).json({ blogs })
    })
    .catch(err => {
        return res.status(500).json({ error: err.message })
    })
});

server.get("/trending-blogs", (req, res) => {
    Blog.find({ draft: false })
    .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
    .sort({ "activity.total_reads": -1, "activity.total_likes": -1, "publishedAt": -1 })
    .select("blog_id title publishedAt -_id")
    .limit(5)
    .then(blogs => {
        return res.status(200).json({ blogs })
    })
    .catch(err => {
        return res.status(500).json({ error: err.message })
    })
});

server.post("/search-blogs", (req, res) => {
    let { tag, page } = req.body;
    
    let findQuery = { tags: tag, draft: false };
    let maxLimit = 5;
    
    Blog.find(findQuery)
    .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
    .sort({ "publishedAt": -1 })
    .select("blog_id title des banner activity tags publishedAt -_id")
    .skip((page - 1) * maxLimit)
    .limit(maxLimit)
    .then(blogs => {
        return res.status(200).json({ blogs })
    })
    .catch(err => {
        return res.status(500).json({ error: err.message })
    })
});

server.post("/count-blogs", (req, res) => {
    Blog.countDocuments({ draft: false })
    .then(count => {
        return res.status(200).json({ totalDocs: count })
    })
    .catch(err => {
        return res.status(500).json({ error: err.message })
    })
});

server.post("/search-count-blogs", (req, res) => {
    let { tag } = req.body;
    
    let findQuery = { tags: tag, draft: false };
    
    Blog.countDocuments(findQuery)
    .then(count => {
        return res.status(200).json({ totalDocs: count })
    })
    .catch(err => {
        return res.status(500).json({ error: err.message })
    })
});

// Create Blog Route
server.post("/create-blog", async (req, res) => {
    try {
        // 1. Authenticate user
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({ error: "No token provided" });
        }
        const token = authHeader.split(" ")[1];
        let userId;
        try {
            const decoded = jwt.verify(token, process.env.SECRET_ACCESS_KEY);
            userId = decoded.id;
        } catch (err) {
            return res.status(401).json({ error: "Invalid or expired token" });
        }

        // 2. Validate input
        const { title, banner, content, tags, des, draft } = req.body;
        if (!title || !banner || !content || !Array.isArray(tags) || tags.length === 0 || !des) {
            return res.status(400).json({ error: "Missing required fields" });
        }

        // 3. Generate unique blog_id
        const blog_id = nanoid();

        // 4. Create and save the blog
        const newBlog = new Blog({
            blog_id,
            title,
            banner,
            content,
            tags,
            des,
            author: userId,
            draft: !!draft
        });
        await newBlog.save();

        // 5. Update user's blogs array and increment total_posts
        await User.findByIdAndUpdate(userId, {
            $push: { blogs: newBlog._id },
            $inc: { "account_info.total_posts": 1 }
        });

        // 6. Return the created blog
        return res.status(201).json({ message: "Blog created successfully", blog: newBlog });
    } catch (error) {
        console.error("/create-blog error:", error);
        return res.status(500).json({ error: error.message || "Failed to create blog" });
    }
});

// Fetch a single blog by blog_id
server.get("/blog/:id", async (req, res) => {
    try {
        const { id } = req.params;
        const blog = await Blog.findOne({ blog_id: id, draft: false })
            .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id");
        if (!blog) {
            return res.status(404).json({ error: "Blog not found" });
        }
        return res.status(200).json({ blog });
    } catch (error) {
        return res.status(500).json({ error: error.message || "Failed to fetch blog" });
    }
});

// Health check endpoint
server.get('/health', (req, res) => {
    res.status(200).json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        firebase_configured: !!serviceAccountKey?.project_id,
        firebase_project: serviceAccountKey?.project_id || 'Not configured',
        environment: process.env.NODE_ENV || 'development',
        cors_origins: [
            "http://localhost:5173",
            "http://localhost:3000", 
            "https://connectfrontend.llp.trizenventures.com",
            "https://connect.trizenventures.com"
        ]
    });
});

// Root endpoint
server.get('/', (req, res) => {
    res.status(200).json({ 
        message: 'Connect Backend API is running',
        endpoints: [
            'GET /health',
            'POST /latest-blogs',
            'GET /trending-blogs',
            'POST /google-auth',
            'POST /signin',
            'POST /signup'
        ]
    });
});

server.listen(PORT,() => {
    console.log('Listening on port -> '+ PORT);
    console.log('Firebase configured:', !!serviceAccountKey?.project_id);
})
