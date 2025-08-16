import express, { json } from 'express';
import mongoose from 'mongoose';
import 'dotenv/config'
import bcrypt from 'bcrypt';
import User from './Schema/User.js';
import Blog from './Schema/Blog.js';
import Comment from './Schema/Comment.js';
import Notification from './Schema/Notification.js';
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
            // User exists - enable account linking
            if (!user.google_auth) {
                console.log("Linking Google account to existing email/password account:", user.personal_info.username);
                
                // Update user to enable Google authentication and update profile picture
                await User.findOneAndUpdate(
                    {"personal_info.email": email},
                    {
                        "google_auth": true,
                        "personal_info.profile_img": picture || user.personal_info.profile_img
                    }
                );
                
                // Fetch updated user data
                user = await User.findOne({"personal_info.email": email})
                    .select("personal_info.fullname personal_info.username personal_info.profile_img google_auth");
                
                console.log("Account successfully linked! User can now sign in with both methods.");
            } else {
                console.log("Existing Google user found:", user.personal_info.username);
            }
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
    let { tag, author, page } = req.body;
    
    let findQuery = { draft: false };
    
    // Add tag filter if provided
    if (tag) {
        findQuery.tags = tag;
    }
    
    // Add author filter if provided
    if (author) {
        findQuery.author = author;
    }
    
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
    let { tag, author } = req.body;
    
    let findQuery = { draft: false };
    
    // Add tag filter if provided
    if (tag) {
        findQuery.tags = tag;
    }
    
    // Add author filter if provided
    if (author) {
        findQuery.author = author;
    }
    
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



// Update Blog Route
server.post("/update-blog", async (req, res) => {
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
        const { id, title, banner, content, tags, des, draft } = req.body;
        if (!id) {
            return res.status(400).json({ error: "Blog ID is required for update" });
        }
        if (!title || !banner || !content || !Array.isArray(tags) || tags.length === 0 || !des) {
            return res.status(400).json({ error: "Missing required fields" });
        }

        // 3. Find the existing blog and verify ownership
        const existingBlog = await Blog.findOne({ blog_id: id });
        if (!existingBlog) {
            return res.status(404).json({ error: "Blog not found" });
        }

        // Check if the user is the author
        if (existingBlog.author.toString() !== userId) {
            return res.status(403).json({ error: "You don't have permission to edit this blog" });
        }

        // 4. Update the blog
        const updatedBlog = await Blog.findOneAndUpdate(
            { blog_id: id },
            {
                title,
                banner,
                content,
                tags,
                des,
                draft: draft !== undefined ? draft : existingBlog.draft
            },
            { new: true }
        ).populate("author", "personal_info.profile_img personal_info.username personal_info.fullname");

        if (!updatedBlog) {
            return res.status(500).json({ error: "Failed to update blog" });
        }

        // 5. Return the updated blog
        return res.status(200).json({ 
            message: "Blog updated successfully", 
            blog: updatedBlog 
        });
    } catch (error) {
        console.error("/update-blog error:", error);
        return res.status(500).json({ error: error.message || "Failed to update blog" });
    }
});

// Fetch a single blog by blog_id
server.get("/blog/:id", async (req, res) => {
    try {
        const { id } = req.params;
        const blog = await Blog.findOne({ blog_id: id, draft: false })
            .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname");
        if (!blog) {
            return res.status(404).json({ error: "Blog not found" });
        }
        return res.status(200).json({ blog });
    } catch (error) {
        return res.status(500).json({ error: error.message || "Failed to fetch blog" });
    }
});

// Profile Management Routes

// Get user profile by username
server.post("/get-profile", async (req, res) => {
    try {
        let { username } = req.body;

        const user = await User.findOne({ "personal_info.username": username })
            .select("-personal_info.password -personal_info.hashed_password -google_auth -updatedAt -blogs");

        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        return res.status(200).json(user);
    } catch (error) {
        console.error("Get profile error:", error);
        return res.status(500).json({ error: error.message || "Failed to fetch profile" });
    }
});

// Update user profile (requires authentication)
server.post("/update-profile", async (req, res) => {
    try {
        // Authenticate user
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

        const { bio, social_links } = req.body;

        // Validate bio length
        if (bio && bio.length > 200) {
            return res.status(400).json({ error: "Bio should not exceed 200 characters" });
        }

        // Update user profile
        const updateData = {};
        if (bio !== undefined) updateData["personal_info.bio"] = bio;
        if (social_links) updateData.social_links = social_links;

        const updatedUser = await User.findByIdAndUpdate(
            userId,
            { $set: updateData },
            { new: true, runValidators: true }
        ).select("-personal_info.password -personal_info.hashed_password -google_auth");

        if (!updatedUser) {
            return res.status(404).json({ error: "User not found" });
        }

        return res.status(200).json({ 
            message: "Profile updated successfully",
            user: updatedUser
        });
    } catch (error) {
        console.error("Update profile error:", error);
        return res.status(500).json({ error: error.message || "Failed to update profile" });
    }
});

// Change password (requires authentication)
server.post("/change-password", async (req, res) => {
    try {
        // Authenticate user
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

        const { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({ error: "Current password and new password are required" });
        }

        // Validate new password
        if (!passwordRegex.test(newPassword)) {
            return res.status(400).json({ 
                error: "New password should be 6 to 20 characters long with a numeric, 1 lowercase and 1 uppercase letter" 
            });
        }

        // Get user
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        // Check if user signed up with Google
        if (user.google_auth) {
            return res.status(400).json({ 
                error: "Cannot change password for Google-authenticated accounts" 
            });
        }

        // Verify current password
        const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.personal_info.hashed_password);
        if (!isCurrentPasswordValid) {
            return res.status(400).json({ error: "Current password is incorrect" });
        }

        // Hash new password
        const hashedNewPassword = await bcrypt.hash(newPassword, 10);

        // Update password
        await User.findByIdAndUpdate(userId, {
            "personal_info.hashed_password": hashedNewPassword
        });

        return res.status(200).json({ message: "Password changed successfully" });
    } catch (error) {
        console.error("Change password error:", error);
        return res.status(500).json({ error: error.message || "Failed to change password" });
    }
});

// Get user's blogs (published and drafts) - requires authentication
server.post("/user-written-blogs", async (req, res) => {
    try {
        // Authenticate user
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

        let { page = 1, draft, deletedDocCount = 0 } = req.body;
        
        let maxLimit = 5;
        let skipDocs = (page - 1) * maxLimit;
        
        if (deletedDocCount) {
            skipDocs -= deletedDocCount;
        }

        const blogs = await Blog.find({ author: userId, draft: !!draft })
            .skip(skipDocs)
            .limit(maxLimit)
            .sort({ publishedAt: -1 })
            .select("title banner publishedAt blog_id activity des draft -_id");

        return res.status(200).json({ blogs });
    } catch (error) {
        console.error("Get user blogs error:", error);
        return res.status(500).json({ error: error.message || "Failed to fetch user blogs" });
    }
});

// Get count of user's blogs - requires authentication
server.post("/user-written-blogs-count", async (req, res) => {
    try {
        // Authenticate user
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

        let { draft } = req.body;
        
        const count = await Blog.countDocuments({ author: userId, draft: !!draft });
        
        return res.status(200).json({ totalDocs: count });
    } catch (error) {
        console.error("Get user blogs count error:", error);
        return res.status(500).json({ error: error.message || "Failed to fetch user blogs count" });
    }
});

// Update profile image (requires authentication)
server.post("/update-profile-img", async (req, res) => {
    try {
        // Authenticate user
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

        const { url } = req.body;

        if (!url) {
            return res.status(400).json({ error: "Profile image URL is required" });
        }

        // Update user profile image
        const updatedUser = await User.findByIdAndUpdate(
            userId,
            { "personal_info.profile_img": url },
            { new: true }
        ).select("personal_info.profile_img");

        if (!updatedUser) {
            return res.status(404).json({ error: "User not found" });
        }

        return res.status(200).json({ 
            message: "Profile image updated successfully",
            profile_img: updatedUser.personal_info.profile_img
        });
    } catch (error) {
        console.error("Update profile image error:", error);
        return res.status(500).json({ error: error.message || "Failed to update profile image" });
    }
});

// Delete blog (requires authentication)
server.post("/delete-blog", async (req, res) => {
    try {
        // Authenticate user
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

        const { blog_id } = req.body;

        if (!blog_id) {
            return res.status(400).json({ error: "Blog ID is required" });
        }

        // Find and verify ownership
        const blog = await Blog.findOne({ blog_id, author: userId });
        if (!blog) {
            return res.status(404).json({ error: "Blog not found or unauthorized" });
        }

        // Delete the blog
        await Blog.findByIdAndDelete(blog._id);

        // Update user's blog count
        await User.findByIdAndUpdate(userId, {
            $pull: { blogs: blog._id },
            $inc: { "account_info.total_posts": -1 }
        });

        return res.status(200).json({ message: "Blog deleted successfully" });
    } catch (error) {
        console.error("Delete blog error:", error);
        return res.status(500).json({ error: error.message || "Failed to delete blog" });
    }
});

// Blog Interaction Routes

// Like/Unlike blog (requires authentication)
server.post("/like-blog", async (req, res) => {
    try {
        // Authenticate user
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

        const { _id, isLikedByUser } = req.body;

        console.log("Like blog request:", { _id, isLikedByUser, userId });

        if (!_id) {
            return res.status(400).json({ error: "Blog ID is required" });
        }

        let incrementVal = !isLikedByUser ? 1 : -1;

        // Update blog like count
        const blog = await Blog.findByIdAndUpdate(_id, {
            $inc: { "activity.total_likes": incrementVal }
        }, { new: true });

        if (!blog) {
            return res.status(404).json({ error: "Blog not found" });
        }

        if (!isLikedByUser) {
            // Add like notification to author (if user is not liking their own blog)
            if (blog.author.toString() !== userId) {
                const notification = new Notification({
                    type: "like",
                    blog: _id,
                    notification_for: blog.author,
                    user: userId
                });
                await notification.save();
            }
        } else {
            // Remove like notification
            await Notification.findOneAndDelete({
                type: "like",
                blog: _id,
                notification_for: blog.author,
                user: userId
            });
        }

        return res.status(200).json({ 
            liked_by_user: !isLikedByUser,
            total_likes: blog.activity.total_likes
        });
    } catch (error) {
        console.error("Like blog error:", error);
        return res.status(500).json({ error: error.message || "Failed to like blog" });
    }
});

// Check if user liked a blog (requires authentication)
server.post("/isliked-by-user", async (req, res) => {
    try {
        // Authenticate user
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

        const { _id } = req.body;

        if (!_id) {
            return res.status(400).json({ error: "Blog ID is required" });
        }

        // Check if user has liked this blog (look for like notification)
        const notification = await Notification.findOne({
            type: "like",
            blog: _id,
            user: userId
        });

        return res.status(200).json({ result: !!notification });
    } catch (error) {
        console.error("Check like status error:", error);
        return res.status(500).json({ error: error.message || "Failed to check like status" });
    }
});

// Add comment to blog (requires authentication)
server.post("/add-comment", async (req, res) => {
    try {
        // Authenticate user
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

        const { _id, comment, blog_author, replying_to, notification_id } = req.body;

        console.log("Add comment request data:", { _id, comment, blog_author, replying_to });

        if (!_id) {
            return res.status(400).json({ error: "Blog ID is required" });
        }

        if (!comment || !comment.trim()) {
            return res.status(400).json({ error: "Comment content is required" });
        }

        if (comment.length > 500) {
            return res.status(400).json({ error: "Comment should not exceed 500 characters" });
        }

        if (!blog_author) {
            return res.status(400).json({ error: "Blog author is required" });
        }

        const commentObj = {
            blog_id: _id,
            blog_author,
            comment,
            commented_by: userId,
            isReply: !!replying_to
        };

        if (replying_to) {
            commentObj.parent = replying_to;
        }

        const newComment = new Comment(commentObj);
        await newComment.save();

        let incrementVal = 1;

        if (replying_to) {
            // Update parent comment's children count
            await Comment.findByIdAndUpdate(replying_to, {
                $push: { children: newComment._id }
            });
            incrementVal = 0; // Don't count replies in blog's total comment count
        }

        // Update blog comment count
        await Blog.findByIdAndUpdate(_id, {
            $push: { comments: newComment._id },
            $inc: { 
                "activity.total_comments": incrementVal,
                "activity.total_parent_comments": replying_to ? 0 : 1
            }
        });

        // Create notification for blog author (if not commenting on own blog)
        if (blog_author !== userId) {
            if (replying_to) {
                // Delete existing reply notification if updating
                if (notification_id) {
                    await Notification.findByIdAndDelete(notification_id);
                }

                // Create reply notification
                const notification = new Notification({
                    type: "reply",
                    blog: _id,
                    notification_for: blog_author,
                    user: userId,
                    comment: newComment._id,
                    replied_on_comment: replying_to,
                    reply: newComment._id
                });
                await notification.save();
            } else {
                // Create comment notification
                const notification = new Notification({
                    type: "comment",
                    blog: _id,
                    notification_for: blog_author,
                    user: userId,
                    comment: newComment._id
                });
                await notification.save();
            }
        }

        // Populate comment with user details for response
        await newComment.populate("commented_by", "personal_info.profile_img personal_info.username personal_info.fullname");

        return res.status(200).json(newComment);
    } catch (error) {
        console.error("Add comment error:", error);
        return res.status(500).json({ error: error.message || "Failed to add comment" });
    }
});

// Get blog comments
server.post("/get-blog-comments", async (req, res) => {
    try {
        const { blog_id, skip = 0 } = req.body;

        if (!blog_id) {
            return res.status(400).json({ error: "Blog ID is required" });
        }

        let maxLimit = 5;

        const comments = await Comment.find({ blog_id, isReply: false })
            .populate("commented_by", "personal_info.profile_img personal_info.username personal_info.fullname")
            .skip(skip)
            .limit(maxLimit)
            .sort({ commentedAt: -1 });

        return res.status(200).json(comments);
    } catch (error) {
        console.error("Get comments error:", error);
        return res.status(500).json({ error: error.message || "Failed to fetch comments" });
    }
});

// Get comment replies
server.post("/get-replies", async (req, res) => {
    try {
        const { _id, skip = 0 } = req.body;

        if (!_id) {
            return res.status(400).json({ error: "Comment ID is required" });
        }

        let maxLimit = 5;

        const replies = await Comment.find({ parent: _id })
            .populate("commented_by", "personal_info.profile_img personal_info.username personal_info.fullname")
            .skip(skip)
            .limit(maxLimit)
            .sort({ commentedAt: -1 });

        return res.status(200).json(replies);
    } catch (error) {
        console.error("Get replies error:", error);
        return res.status(500).json({ error: error.message || "Failed to fetch replies" });
    }
});

// Delete comment (requires authentication)
server.post("/delete-comment", async (req, res) => {
    try {
        // Authenticate user
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

        const { _id } = req.body;

        if (!_id) {
            return res.status(400).json({ error: "Comment ID is required" });
        }

        // Find comment and verify ownership or blog ownership
        const comment = await Comment.findById(_id);
        if (!comment) {
            return res.status(404).json({ error: "Comment not found" });
        }

        // Check if user is comment owner or blog author
        const blog = await Blog.findById(comment.blog_id);
        if (comment.commented_by.toString() !== userId && blog.author.toString() !== userId) {
            return res.status(403).json({ error: "Unauthorized to delete this comment" });
        }

        // Delete comment and all its replies
        await Comment.findByIdAndDelete(_id);
        await Comment.deleteMany({ parent: _id });

        // Update blog comment counts
        const parentCommentsCount = await Comment.countDocuments({ 
            blog_id: comment.blog_id, 
            isReply: false 
        });
        
        const totalCommentsCount = await Comment.countDocuments({ 
            blog_id: comment.blog_id 
        });

        await Blog.findByIdAndUpdate(comment.blog_id, {
            $pull: { comments: _id },
            $set: {
                "activity.total_parent_comments": parentCommentsCount,
                "activity.total_comments": totalCommentsCount
            }
        });

        // Delete related notifications
        await Notification.deleteMany({
            $or: [
                { comment: _id },
                { replied_on_comment: _id }
            ]
        });

        return res.status(200).json({ message: "Comment deleted successfully" });
    } catch (error) {
        console.error("Delete comment error:", error);
        return res.status(500).json({ error: error.message || "Failed to delete comment" });
    }
});

// Follow/Unfollow Routes

// Follow/Unfollow user (requires authentication)
server.post("/follow-user", async (req, res) => {
    try {
        // Authenticate user
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

        const { user_id, isFollowing } = req.body;

        console.log("Follow request:", { user_id, isFollowing, followerId: userId });

        if (!user_id) {
            return res.status(400).json({ error: "User ID is required" });
        }

        if (user_id === userId) {
            return res.status(400).json({ error: "Cannot follow yourself" });
        }

        // Check if target user exists
        const targetUser = await User.findById(user_id);
        if (!targetUser) {
            return res.status(404).json({ error: "User not found" });
        }

        if (!isFollowing) {
            // Follow user
            await User.findByIdAndUpdate(userId, {
                $addToSet: { following: user_id }
            });
            
            await User.findByIdAndUpdate(user_id, {
                $addToSet: { followers: userId }
            });

            // Create follow notification
            const notification = new Notification({
                type: "follow",
                notification_for: user_id,
                user: userId
            });
            await notification.save();

            return res.status(200).json({ 
                following: true,
                message: "User followed successfully"
            });
        } else {
            // Unfollow user
            await User.findByIdAndUpdate(userId, {
                $pull: { following: user_id }
            });
            
            await User.findByIdAndUpdate(user_id, {
                $pull: { followers: userId }
            });

            // Remove follow notification
            await Notification.findOneAndDelete({
                type: "follow",
                notification_for: user_id,
                user: userId
            });

            return res.status(200).json({ 
                following: false,
                message: "User unfollowed successfully"
            });
        }
    } catch (error) {
        console.error("Follow user error:", error);
        return res.status(500).json({ error: error.message || "Failed to follow/unfollow user" });
    }
});

// Check if user is following another user (requires authentication)
server.post("/is-following", async (req, res) => {
    try {
        // Authenticate user
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

        const { user_id } = req.body;

        if (!user_id) {
            return res.status(400).json({ error: "User ID is required" });
        }

        // Check if current user is following the target user
        const currentUser = await User.findById(userId);
        const isFollowing = currentUser.following.includes(user_id);

        console.log("Follow status check:", { userId, user_id, isFollowing, followingArray: currentUser.following });

        return res.status(200).json({ result: isFollowing });
    } catch (error) {
        console.error("Check following status error:", error);
        return res.status(500).json({ error: error.message || "Failed to check following status" });
    }
});

// Get user followers count
server.post("/get-followers-count", async (req, res) => {
    try {
        const { user_id } = req.body;

        if (!user_id) {
            return res.status(400).json({ error: "User ID is required" });
        }

        const user = await User.findById(user_id);
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        return res.status(200).json({ 
            followers_count: user.followers.length,
            following_count: user.following.length
        });
    } catch (error) {
        console.error("Get followers count error:", error);
        return res.status(500).json({ error: error.message || "Failed to get followers count" });
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
            'POST /signup',
            'POST /get-profile',
            'POST /update-profile',
            'POST /update-profile-img',
            'POST /change-password',
            'POST /user-written-blogs',
            'POST /user-written-blogs-count',
            'POST /delete-blog',
            'POST /like-blog',
            'POST /isliked-by-user',
            'POST /add-comment',
            'POST /get-blog-comments',
            'POST /get-replies',
            'POST /delete-comment',
            'POST /follow-user',
            'POST /is-following',
            'POST /get-followers-count'
        ]
    });
});

server.listen(PORT,() => {
    console.log('Listening on port -> '+ PORT);
    console.log('Firebase configured:', !!serviceAccountKey?.project_id);
    console.log('CORS configuration active - Build v2.0');
})
