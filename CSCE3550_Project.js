import http from "http";                //Imports HTTP Module for Server
import crypto from "crypto";            //Imports Crypto Module for RSA Implementation
import {v4 as uuidv4} from 'uuid';      //Imports UUID Module for Unique IDS
import jwt from "jsonwebtoken";         //Imports JTW Module for JTW Functionality
import sqlite3 from 'sqlite3';          //Imports SQLite3 Module for Database Functionality
import express from "express";          //Imports Express Module for Connections
import argon2 from "argon2";            //Imports Argon2 Module for Password Hashing
const HOSTNAME = "127.0.0.1";           //Hostname for the Server
const PORT = 8080;                      //The Port of the Server for Incoming Requests
const DB = new sqlite3.Database("./totally_not_my_privateKeys.db"); //Database to store private keys
const APP = express();

APP.use(express.json());

//Functionality One - Generate RSA Key Pair
function generateKeyPair(isExpired = false)
{
    //Defines Public and Private Keys
    const {publicKey, privateKey} = crypto.generateKeyPairSync("rsa", 
    {
        modulusLength: 2048,
        publicKeyEncoding: {type: "spki", format: "pem"},
        privateKeyEncoding: {type: "pkcs8", format: "pem"}
    });

    //Returns the Unique ID, Private and Public Keys, and Expiration Time
    return {
        kid: uuidv4(),
        publicKey,
        privateKey,
        expiresAt: isExpired ? Date.now() - (60 * 1000) : Date.now() + (5 * 60 * 1000)
    };
}

//Functionality Two - Store Private Keys to the SQLite Database
function storePrivateKeys()
{
    //Prints info for stuff
    for (let i = 0; i < keys.length; i++)
    {
        let encryptedPrivateKey = encryptPrivateKeys(keys[i].privateKey);
        DB.run("INSERT INTO keys(key, exp) VALUES(?, ?)", [encryptedPrivateKey, keys[i].expiresAt]);
    }
}

//Functionality Three - Public Key to JWKS Format
function publicKeyToJWK(publicKeyPem, kid)
{
    //Creates a Public Key
    const publicKeyObj = crypto.createPublicKey(publicKeyPem);

    //Converts Public Key to JWK Format
    const jwk = publicKeyObj.export({format : "jwk"});

    //Returns Key Type, Key Id, Use Signature, Algorithm, Modulus, and Exponent
    return {
        kty: "RSA",
        kid: kid,
        use: "sig",
        alg: "RS256",
        n: jwk.n,
        e: jwk.e
    };
}

//Fuctionality Four - Generate Keys
let keys = [];
keys.push(generateKeyPair(false));
keys.push(generateKeyPair(true));

//Functionality Five - Encrypting Private Keys
function encryptPrivateKeys(text)
{
    let cipher = crypto.createCipheriv("aes-128-cbc", "1272025448679420", "1272025448679420");
    let encrypted = cipher.update(text, "utf8", "hex");
    encrypted += cipher.final("hex");
    return encrypted;
}

//Functionality Five - Serve the JWKS
function getJWKS()
{
    //Create an array of valid keys
    const validKeys = keys.filter(k => k.expiresAt > Date.now());

    //Returns keys for the server
    return {
        keys: validKeys.map(k => publicKeyToJWK(k.publicKey, k.kid))
    };
}

//Fuctionality Six - Handling Autherization
function handleAuth(res, url)
{
    //Checks if the URL's keys are expired
    const expired = url.searchParams.get("expired") === "true";

    let key;
    if (expired)
    {
        //Keys are Expired
        key = keys.find(k => k.expiresAt < Date.now());
    }
    else
    {
        //Keys are NOT Expired
        key = keys.find(k => k.expiresAt > Date.now());
    }

    //Key is NOT Found
    if (!key)
    {
        res.writeHead(500, {'Content-Type' : 'application/json'});
        res.end(JSON.stringify({error: "No suitable key found"}));
        return;
    }

    //Calculates the current now time in seconds
    const now = Math.floor((Date.now() / 1000));

    //Data to Transfer
    const payload = {
        user: "test-user",
        iat: now,
        exp: expired ? now - 60: now + 5 * 60
    };

    //Signs the JWT Token
    const token = jwt.sign(payload, key.privateKey, {
        algorithm: "RS256",
        keyid: key.kid,
    });

    res.writeHead(200, {'Content-Type' : 'application/json'});
    res.end(JSON.stringify({token}));
}

//Functionality Seven - Store user registration data to Users table in the database
async function userRegister(userData, res)
{
    //Reads Client's username and email
    const { username, email } = userData;

    //Generates password
    let password = uuidv4();
    const passwordHash = await argon2.hash(password);

    //Translates Javascript Date to SQL Timestamp
    let jsDate = new Date();
    const isoString = jsDate.toISOString();
    const sqlTime = isoString.slice(0, 19).replace('T', ' ');

    //Insert usernames and emails from the client and passwords generated from the sever into the Users table in the Database
    DB.run("INSERT INTO users(username, password_hash, email, date_registered, last_login) VALUES(?, ?, ?, ?, ?) RETURNING *",
        [username, passwordHash, email, sqlTime, sqlTime]);

    //Returns an OK status, and reponds with Userdata info
    res.writeHead(200, {'Content-Type' : 'application/json'});
    res.end(JSON.stringify({password}));
}

//Stores Private Keys to the Database before startup
storePrivateKeys();

//Functionality Eight - The Main Server Function
const server = http.createServer((req, res) => {
    //Creates URL for JWKS Server
    const url = new URL(req.url, `http://${req.headers.host}`);

    //Directs user to different pages in Server
    //Main Page
    if (url.pathname === '/' && req.method === 'GET') {
        res.writeHead(200, {'Content-Type' : 'text/plain'});
        res.end("Welcome to the JWKS Server! Visit /.well-known/jwks.json to see the keys.");
    }
    //Key Page
    else if (url.pathname === '/.well-known/jwks.json' && req.method === "GET")
    {
        const jwks = getJWKS();
        res.writeHead(200, {'Content-Type' : 'application/json'});
        res.end(JSON.stringify(jwks, null, 2));
    }
    //Auth Page
    else if (url.pathname === '/auth' && req.method === 'POST')
    {
        handleAuth(res, url);
    }
    else if (url.pathname === "/register" && req.method === "POST")
    {
        //Sets body
        let body = "";

        //Turns the info from client into string
        req.on("data", (chunk) => {body += chunk.toString()});
        req.on("end", () => {
            //Parses body into JSON format
            const userData = JSON.parse(body);
            userRegister(userData, res);
        });
    }
    //Error Page
    else
    {
        res.writeHead(405, {'Content-Type' : 'text/plain'});
        res.end("Method Not Allowed");
    }
});

//Fuctionality Nine - Opens Up the Server
server.listen(PORT, HOSTNAME, () => {
    console.log(`Server running at http://${HOSTNAME}:${PORT}`);
});
