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
import serviceAccountKey from "./react-js-blog-website-yt-ded86-firebase-adminsdk-lmrz6-e9d71ed613.json"  with {type : 'json'};
import aws from "aws-sdk";


const server = express();
let PORT = 3000;

admin.initializeApp({
    credential: admin.credential.cert(serviceAccountKey)
})

let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/; // regex for email
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/; // regex for password

server.use(express.json());
server.use(cors({
  origin: [
    "http://localhost:5173",
    "https://connectfrontend.llp.trizenventures.com"
  ],
  credentials: true
}))
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

server.post("/google-auth", async (req,res) => {
    let { access_token } = req.body;

    getAuth()
    .verifyIdToken(access_token)
    .then(async (decodedUser) => {

        let {email, name, picture} = decodedUser;

        picture = picture.replace("s96-c", "s384-c");

        let user = await User.findOne({"personal_info.email": email}).select("personal_info.fullname profile_info.username personal_info.profile_img google_auth").then((u) => {
            return u || null
        })
        .catch(err => {
            return res.status(500).json({"error":err.message})
        })

        if(user){ //login
            if(user.google_auth){
                return res.status(403).json({"error":"This email was signed up without google. Please log in with password to access the account "})
            }
        }
        else{//sign up
            let username = await generateUsername(email);

            user = new User({
                personal_info: { fullname: name, email, profile_img: picture, username},
                google_auth : true
            })

            await user.save().then((u) => {
                user = u;
            })
            .catch(err => {
                return res.status(500).json({"error":err.message})
            })
        }

        return res.status(200).json(formatDatatoSend(user))

    })
    .catch(err => {
        return res.status(500).json({"error":"Failed to authenticate you with google. Try with some other google account"})
    })

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

server.listen(PORT,() => {
    console.log('Listening on port -> '+ PORT);
})
