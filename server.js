let config 		= require('./config.json');
let database 	= require('./db.js');

let express 		= require('express'),
	bodyParser 		= require('body-parser'),
	exphbs  		= require('express-handlebars'),
	cookieSession 	= require('cookie-session');	

var hbs = exphbs.create({

	defaultLayout: 'site'
});


let app = express();

app.use('/assets', express.static('assets'));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); 

app.engine('handlebars', hbs.engine);
app.set('view engine', 'handlebars');

app.use(cookieSession({
	name: 'session',
	secret: 'secret to encrypt decrypt cookie',
	maxAge: 24 * 60 * 60 * 1000 // 24 hours
}))


app.use('/', require('./routes') );


app.listen(config.port, config.host, function(err, res){

	if( err ) {

		console.log( err );
		process.exit(1);
	}

	console.log("Server running on http://"+config.host+":"+config.port);	
});
