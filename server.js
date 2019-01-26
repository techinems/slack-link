const env = require('dotenv').config();
const crypto = require('crypto');
const request = require('request');
const express = require('express');
const bodyParser = require('body-parser');
const qs = require('qs');

//If the environment variables don't get loaded
if(env.error){
    throw env.error
}

// Load in the environment variables
const slackVerificationToken = process.env.SLACK_VERIFICATION_TOKEN;
const slackAccessToken = process.env.SLACK_ACCESS_TOKEN;
const slackSigningSecret = process.env.SLACK_SIGNING_SECRET;

// Initializes express app
const app = express();
app.use(bodyParser.urlencoded({extended: false}));

// Middleware to hopefully handle slack requests
app.use('/slack/slack-link/commands', function(req,res,next){
    var slackSignature = req.headers['x-slack-signature'];
    var requestBody = qs.stringify(req.body,{ format:'RFC1738' });
    var timestamp = req.headers['x-slack-request-timestamp'];
    // convert current time from milliseconds to seconds
    const time = Math.floor(new Date().getTime()/1000);
    // Most likely a replay attack
    if (Math.abs(time - timestamp) > 300) {
        return res.status(400).send('Ignore this request.');
    }
    var sigBasestring = 'v0:' + timestamp + ':' + requestBody;
    var mySignature = 'v0=' + 
                   crypto.createHmac('sha256', slackSigningSecret)
                         .update(sigBasestring, 'utf8')
                         .digest('hex');
    // Safe against timing attacks
    if(crypto.timingSafeEqual(Buffer.from(mySignature,'utf8'), Buffer.from(slackSignature,'utf8'))){
        next();
    }else{
        return res.status(400).send('Request verification failed');
    }
});

app.post('/slack/slack-link/commands', slackSlashCommands);

// Initializes server on PORT 3000
app.listen(3000,function(){
    console.log("Started on PORT 3000");
})

function slackSlashCommands(req, res){
    var req_body = req.body;
    var command = req_body.command;
    // Link user command
    if(command == "/linkuser"){
        var text = req_body.text
        text = text.split(" ");
        var user = text[0];
        // Means it's most likely not a user
        if(user.indexOf("<") != 0){
            res.send("The first paramter must be a user!");
            return;
        }

        user = user.substring(0,user.indexOf("|"));
        user += ">";
        var web_id = text[1];
        if(isNaN(web_id)){
            res.send("The second paramater must be a whole number!");
            return;
        }

        // Sends the post request to rpiambulance.com 
        request.post({
            url:'https://rpiambulance.com/slack-link.php', 
            form: {slack_id: user, member_id: web_id}
        }, function(err,response,body){
            if (!err && response.statusCode == 200) {
                return res.send(body);
            }else{
                var message = "Oops! Something happened with that server request, please try again later.";
                return res.send(message);
            }
            
        });
    }else{
        // This gets hit if slack sends a post to this app but we didn't program for that command
        console.log("Command not configured!");
        res.send("It appears the command you are trying to send isn't support");
    }
}