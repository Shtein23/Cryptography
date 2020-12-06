// Зависимости
var bodyParser = require('body-parser');
var express = require('express');
const hbs = require("hbs");
var http = require('http');
var path = require('path');
var md5 = require('md5');
var CodeGenerator = require('node-code-generator');
var users = require('./bd/bd');
var codeHash = require('./bd/code');
var fs = require('fs');
const nodemailer = require('nodemailer');
var cookieParser = require('cookie-parser');
const publicDir = require('path').join(__dirname,'/public');
const expressHbs = require("express-handlebars");

var app = express();
var server = http.Server(app);

app.engine("hbs", expressHbs(
    {
        layoutsDir: "views/layouts", 
        defaultLayout: "layout",
        extname: "hbs"
    }
))


app.set("view engine", "hbs");

// // Запуск сервера
server.listen(3333, function() {
    console.log('Запускаю сервер на порте 3333');
});


// Для отправки сообщений на почту неободимо ввести данные от существующего email
let EMAIL = 'test@test.ru'
let HOST = 'mail.test.ru'
let PASS = '12345'

let transporter = nodemailer.createTransport({
    host: HOST,
    port: 25,
    secure: false,
    auth: {
        user: EMAIL,
        pass: PASS,
        },
    })

//======================================================ЗАПИСЬ В ФАЙЛ=================================

function writeFile(bdJson, nameBd) {
var string = JSON.stringify(bdJson,null,'\t');

    fs.writeFile(nameBd,string,function(err) {
        if(err) return console.error(err);
    })
}
//====================================================================================================

//======================================================ГЕНЕРАЦИЯ ВРЕМЕННОГО КОДА=====================
function codeGenerator(){
    var generator = new CodeGenerator();
    var pattern = '######';
    var howMany = 1;
    var options = {};
    var codes = generator.generateCodes(pattern, howMany, options);
    return codes[0]
}
//====================================================================================================

//======================================================ПРОВЕРКА ЗАРЕГЕТРИРОВАННОГО EMAIL=============
function checkMail(mail, arr){
    var flag1 = true
    var usersLenght = Object.keys(users).length;
    for (let i = 0; i < usersLenght; i++) { 
        if (arr[Object.keys(arr)[i]].email == mail){
            flag1 = false;
            return flag1
        }
    }
    return flag1
}
//====================================================================================================

//======================================================ПРОВЕРКА COOKIE===============================
function checkCookies(files, a, res, title){
    if ((a) && (users[a.split(' ')[0]].cookie == a.split(' ')[1])){
        return res.redirect(301, '/profile');

    } else {
        return res.render(files, {title: title})

    }
}

//====================================================================================================


app.use(cookieParser());
app.use(express.static(publicDir));
const urlencodedParser = bodyParser.urlencoded({extended: false});

// Маршруты
app.get('/', function(request, response) {
    checkCookies('index.hbs', request.cookies['SecondStep'], response, "Главная страница")
});
app.get("/SignUp", urlencodedParser, function (request, response) {
    checkCookies("SignUp.hbs", request.cookies['SecondStep'], response, "Регистрация")
});

app.get("/SignIn", urlencodedParser, function (request, response) {
    checkCookies("SignIn.hbs", request.cookies['SecondStep'], response, "Авторизация")
});



app.post("/SignUp", urlencodedParser, function (request, response) {

    if (!checkMail(request.body.email, users)){
        return response.render("SignUp", {errMail: 'Email '+request.body.email+'уже зарегестрирован', normLogin: request.body.login})
    } else if (typeof users[request.body.login] != "undefined"){
        return response.render("SignUp", {errMail: '', errLogin: 'Login '+request.body.login+' занят', normMail: request.body.email})
    } else {
        users[request.body.login] = {
          email: request.body.email,
          pass: request.body.pass,
          cookie: '',
          hash: 0,
          ttlHash: 0,
          isOnline: false
        }

        writeFile(users, './bd.json')

        if(!request.body) return response.sendStatus(400);

        response.redirect(301, '/');
        
    }
});

app.get("/login", function (request, response) {
    response.redirect(301, '/SignIn');
});

app.get("/CodeAuth", function (request, response) {
    response.redirect(301, '/SignIn');
});

app.post("/login", urlencodedParser, function (request, response) {
    if ((typeof users[request.body.login] != "undefined") && (users[request.body.login].pass == request.body.pass) 
        && (users[request.body.login].ttlHash < (Math.floor(Date.now()/1000) - 300))){

        users[request.body.login].ttlHash = Math.floor(Date.now()/1000);
        codeUser = codeGenerator();
        users[request.body.login].hash = md5(codeUser);
        var ttl = Math.floor(Date.now()/1000) + 30;
        codeHash[md5(codeUser)] = {
          TTL: ttl,
          login: request.body.login
        }

        writeFile(codeHash, './code.json')
        var message = {
                from: 'fea@pps.ru',
                to: users[request.body.login].email,
                subject: 'Confirm auth on Website',
                text: 'Please confirm your auth',
                html: '<p>Please confirm your auth with this code: '+codeUser+'</p>'
            };
        transporter.sendMail(message, (error, info) => {
            if (error) {
                return console.log(error);
            }
        });
        users[request.body.login].cookie = md5(codeGenerator())
        response.cookie('FirstStep', request.body.login + ' ' + users[request.body.login].cookie, {maxAge: 300000*4,httpOnly: true})
        response.redirect("/CodeEnter")
        app.get("/CodeEnter", urlencodedParser, function (request, response) {

            var checkCookie = request.cookies['FirstStep']
            if (checkCookie) {
                var checkCookie1 = checkCookie.split(' ')
                if (users[checkCookie1[0]].cookie == checkCookie1[1]){
                    return response.redirect("/ConfirmAuth")
                } 
            } else {
                return response.redirect("/SignIn");
            }
        });

    } else if ((typeof users[request.body.login] == "undefined") || (users[request.body.login].pass != request.body.pass)) {

        return response.render("SignIn.hbs", {title: "Регистрация", errCode: 'Неправильно введены логин или пароль'})
    
    } else if ((users[request.body.login].ttlHash > (Math.floor(Date.now()/1000) - 300))){
        return response.redirect("/ConfirmAuth")
    }

});


app.get("/ConfirmAuth", function(request, response){

    let cc = request.cookies['FirstStep']
    if ((cc) && (users[cc.split(' ')[0]].cookie == cc.split(' ')[1])){
        return response.render('CodeAuth.hbs', {title: "Код подтверждения", class1: "d-none"})
    } else {
        return response.redirect(301, '/');
    }

});

app.post("/CodeAuth", urlencodedParser, function (request, response) {
    

    var mass = request.body.code
    var userCodeMd5 = md5(mass);
    var ttlCheck = Math.floor(Date.now()/1000);

    if ((typeof codeHash[userCodeMd5] != "undefined") && (request.cookies['FirstStep']) 
        && (request.cookies['FirstStep'].split(' ')[0] == codeHash[userCodeMd5].login) 
        && (request.cookies['FirstStep'].split(' ')[1] == users[codeHash[userCodeMd5].login].cookie) 
        && (userCodeMd5 = users[codeHash[userCodeMd5].login].hash) && (codeHash[userCodeMd5].TTL > ttlCheck)){

        users[codeHash[userCodeMd5].login].cookie = md5(codeGenerator());
        users[codeHash[userCodeMd5].login].isOnline = true
        users[codeHash[userCodeMd5].login].ttlHash = 0


        response.clearCookie('FirstStep');
        response.cookie('SecondStep', codeHash[userCodeMd5].login + ' ' + users[codeHash[userCodeMd5].login].cookie, {maxAge: 3600000,httpOnly: true});
        response.redirect(301, '/profile');

        users[codeHash[userCodeMd5].login].hash = 0;
        writeFile(users, './bd.json')
    } else if (typeof codeHash[userCodeMd5] == "undefined"){
        
        return response.render('CodeAuth.hbs', {title: "Код подтверждения", code: 'Код введен неправильно'})

    } else if (codeHash[userCodeMd5].TTL < ttlCheck) {

        response.render('CodeAuth.hbs', {title: "Код подтверждения", code: 'Время действия кода истекло'})

    } else if (!request.cookies['FirstStep']){

        return response.redirect("/SignIn")

    }
});

app.get("/profile", urlencodedParser, function (request, response) {
    var bb = request.cookies['SecondStep']
    if ((bb) && (users[bb.split(' ')[0]].cookie == bb.split(' ')[1])){

        return response.render("profile.hbs", {username: bb.split(' ')[0], title: bb.split(' ')[0] + " | Профиль"});

    } else {

        return response.redirect(301, '/');
    }
});

app.get("/out", function (request, response) {
    users[request.cookies['SecondStep'].split(' ')[0]].isOnline = false;
    users[request.cookies['SecondStep'].split(' ')[0]].cookie = 0;
    response.clearCookie('SecondStep');
    response.redirect(301, '/');
    writeFile(users, './bd.json')

});

