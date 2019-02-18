let config = require('./config.json');

let mongoose 	= require('mongoose'),
	crypto 		= require('crypto');


let connection_string = 'mongodb://';
if( config.db_user && config.db_pass ) {
	connection_string += config.db_user+':'+config.db_pass+'@';
}
connection_string += config.db_host+':'+config.db_port+'/'+config.db_name;
if( config.db_auth ) {
	connection_string += '?authSource='+config.db_auth;
}


mongoose.connect(connection_string, { useNewUrlParser: true } );
let db = mongoose.connection;

db.on('error', function(err){

	console.log("Error in connecting with MongoDB");
	console.log(err);
	process.exit(1);
});

db.once('open', function callback() {
	
    console.log("Connection with database succeeded.");
});

let encryptPassword = function( password ) {

	return crypto.createHash('sha256').update(password).digest('hex');
}

let userSchema = mongoose.Schema({
	name: String,
	email: String,
	password: String,
	created_on: {
		type: Date,
		default: Date.now
	}
});

userSchema.statics.insertUser = function( name, email, password, callback ) {

	let user = new UserModel;
    user.name = name;
    user.email = email;
    user.password = encryptPassword(password);
    user.save( function( err, user_data ) {

	    if ( err ) {

	        return callback({ message: err.message, code: 'Error in creating user' });
	    }

	    callback( null, user_data );
	})
}

userSchema.statics.findUser = function( email, password, callback ) {

	UserModel.findOne({
		email: email,
		password: encryptPassword(password)
	}, callback )
}

userSchema.statics.findUserByEmail = function( email, callback ) {

	UserModel.findOne({
		email: email
	}, callback )
}

let UserModel = mongoose.model("User", userSchema);




let authTokenSchema = mongoose.Schema({
	token: {
		type: String,
		require: true
	},
	user_id: {
		type: mongoose.Schema.Types.ObjectId,
		require: true
	},
	created_on: {
		type: Date,
		default: Date.now
	},
	is_valid:{

		type: Boolean,
		default: true
	}
}) 

authTokenSchema.statics.generateToken = function( user_id, callback ) {

	let token = new AuthTokenModel;
	token.user_id = user_id;
	token.token = crypto.randomBytes(64).toString('hex');
	token.save( function( err, token_data ) {

	    if ( err ) {

	        return callback({ message: err.message, code: 'Error in creating token' });
	    }

	    callback( null, token_data );
	})	
}

authTokenSchema.statics.verifyToken = function( user_id, token, callback ) {

	AuthTokenModel.findOne({
		user_id: user_id,
		token: token,
		is_valid: true
	}, callback )
}

authTokenSchema.statics.invalidateToken = function( user_id, token, callback ) {

	AuthTokenModel.updateOne({
		user_id: user_id,
		token: token,
	},{
		$set:{
			is_valid: false
		}
	}, callback )
}

let AuthTokenModel = mongoose.model("AuthToken", authTokenSchema);



exports.UserModel = UserModel;
exports.AuthTokenModel = AuthTokenModel;