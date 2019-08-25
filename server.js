const env = require('dotenv').config();
const crypto = require('crypto');
const request = require('request');
const express = require('express');
const bodyParser = require('body-parser');
const qs = require('qs');

//If the environment variables don't get loaded
if (env.error) {
    throw env.error
}

// Load in the environment variables
const slackAccessToken = process.env.SLACK_ACCESS_TOKEN;
const slackSigningSecret = process.env.SLACK_SIGNING_SECRET;
const websiteVerificationToken = process.env.WEBSITE_VERIFICATION_TOKEN;

// Initializes express app
const app = express();
app.use(bodyParser.urlencoded({ extended: false }));

// Middleware to hopefully handle slack requests
app.use('/slack/slack-link/commands', function (req, res, next) {
    let slackSignature = req.headers['x-slack-signature'];
    let requestBody = qs.stringify(req.body, { format: 'RFC1738' });
    let timestamp = req.headers['x-slack-request-timestamp'];
    // convert current time from milliseconds to seconds
    const time = Math.floor(new Date().getTime() / 1000);
    // Most likely a replay attack
    if (Math.abs(time - timestamp) > 300) {
        return res.status(200).send('Ignore this request.');
    }
    let sigBasestring = 'v0:' + timestamp + ':' + requestBody;
    let mySignature = 'v0=' +
        crypto.createHmac('sha256', slackSigningSecret)
            .update(sigBasestring, 'utf8')
            .digest('hex');
    // Safe against timing attacks
    if (crypto.timingSafeEqual(Buffer.from(mySignature, 'utf8'), Buffer.from(slackSignature, 'utf8'))) {
        next();
    } else {
        return res.status(200).send('Request verification failed');
    }
});

app.post('/slack/slack-link/commands', slackSlashCommands);

// Initializes server on PORT 4000
app.listen(4000, function () {
    console.log("Started on PORT 4000");
})

function slackSlashCommands(req, res) {
    let command = req.body.command;
    // Link user command
    if (command == "/linkuser") {
        linkUser(req, res);
    } else if (command == "/checklink") {
        // I felt the code was getting a little cluttered so I moved the command into a function
        checkUserLink(req, res);
    } else if (command == "/memberinfo") {
        memberInfo(req, res);
    } else {
        // This gets hit if slack sends a post to this app but we didn't program for that command
        console.log("Command not configured!");
        res.send("It appears the command you are trying to send isn't support");
    }
}

function checkUserLink(req, res) {
    let req_body = req.body;
    // The paramaters after the command
    let text = req_body.text;
    // Puts it in the format that database has
    let user = "<@" + req_body.user_id + ">";
    let rpia_query_url = `https://rpiambulance.com/slack-link.php?token=${websiteVerificationToken}&slack_id=`;
    // If they gave us no paramaters just return themselves
    if (text.length == 0) {
        // Encodes the userID of who initialized the command to be sent
        rpia_query_url += encodeURIComponent(user);
    } else {
        text = text.split(" ");
        user = text[0];
        // Means it's most likely not a user
        if (user.indexOf("<") != 0) {
            res.send("The first paramter must be a user!");
            return;
        }
        // We chop off the username as slack is deprecating this
        user = user.substring(0, user.indexOf("|"));
        user += ">";
        rpia_query_url += encodeURI(user);
    }
    // Here's where we make the actual request to RPIA servers
    request.get(rpia_query_url, function (error, resp, body) {
        if (!error && resp.statusCode == 200) {
            // Whatever the website returns is the message we will use.
            return res.send(body);
        } else {
            return res.send("Oops! Something went wrong with the server request to RPIA!");
        }
    });
}

function linkUser(req, res) {
    const req_body = req.body;
    if (!(isAdmin(req_body.user_id))) {
        return res.send("This command can only be used by an admin!");
    } else {
        let text = req_body.text
        text = text.split(" ");
        let user = text[0];
        // Means it's most likely not a user
        if (user.indexOf("<") != 0) {
            res.send("The first paramter must be a user!");
            return;
        }

        user = user.substring(0, user.indexOf("|"));
        user += ">";
        let web_id = text[1];
        if (isNaN(web_id)) {
            res.send("The second paramater must be a whole number!");
            return;
        }

        // Sends the post request to rpiambulance.com 
        request.post({
            url: 'https://rpiambulance.com/slack-link.php',
            form: { slack_id: user, member_id: web_id, token: websiteVerificationToken }
        }, function (err, response, body) {
            if (!err && response.statusCode == 200) {
                return res.send(body);
            } else {
                let message = "Oops! Something happened with that server request, please try again later.";
                return res.send(message);
            }

        });
    }
}

function memberInfo(req, res) {
    const req_body = req.body;
    // The paramaters after the command
    let text = req_body.text;
    // Puts it in the format that database has
    let user = "<@" + req_body.user_id + ">";
    let rpia_query_url = `https://rpiambulance.com/slack-link.php?token=${websiteVerificationToken}&type=info&slack_id=`;
    // If they gave us no paramaters just return themselves
    if (text.length == 0) {
        // Encodes the userID of who initialized the command to be sent
        rpia_query_url += encodeURIComponent(user);
    } else {
        text = text.split(" ");
        user = text[0];
        // Means it's most likely not a user
        if (user.indexOf("<") != 0) {
            res.send("The first paramter must be a user!");
            return;
        }
        // We chop off the username as slack is deprecating this
        user = user.substring(0, user.indexOf("|"));
        user += ">";
        rpia_query_url += encodeURI(user);
    }
    // Add the fact that the user is an admin so they can get more information
    if (isAdmin(req_body.user_id)) {
        rpia_query_url += "admin=1";
    }
    // Here's where we make the actual request to RPIA servers
    request.get(rpia_query_url, function (error, resp, body) {
        if (!error && resp.statusCode == 200) {
            // Whatever the website returns is the message we will use.
            return res.send(body);
        } else {
            console.log(rpia_query_url);
            return res.send("Oops! Something went wrong with the server request to RPIA!");
        }
    });
}

function isAdmin(userId) {
    const slack_userinfo_url = "https://slack.com/api/users.info?token=" + slackAccessToken + "&user=" + userId;
    request.get(slack_userinfo_url, function (error, resp, bod) {
        if (!error && resp.statusCode == 200) {
            bod = JSON.parse(bod);
            return bod.user.is_admin
        } else {
            console.error(`Bad Admin Request: ${error}`);
        }
        return false;
    });
}