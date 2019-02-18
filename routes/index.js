let express 		= require('express'),
	async 			= require('async');

let config 			= require('../config.json');

let router 			= express.Router();

let db = require('../db.js');

router.get('/', function(req, res){

	//res.send( req.session );return;

	async.waterfall([

			function( next ) {

				const session = req.session;
				if( !session.hasOwnProperty('token') || 
					!session.hasOwnProperty('email') ||
					!session.hasOwnProperty('name') ){

					next( {code: 'NOT_LOGIN'} )
				} else {

					next(null, session)
				}
			}, function( session_data, next ) {

				db.UserModel.findUserByEmail( session_data.email, function( err, user_data ) {

					next( err, session_data, user_data );
				} )
			}, function( session_data, user_data, next ) {

				db.AuthTokenModel.verifyToken( user_data._id, session_data.token, function( err ) {

					next( err, session_data );
				})
			}
		], function( err, result ) {

			if( err && err.code == 'NOT_LOGIN' ) {

				res.redirect('/login');
			} else {

				res.render('home',{
					user_name: result.name
				})
			}
		})
});

router
	.get('/logout', function( req, res ) {

		const session = req.session;
		if( !session.hasOwnProperty('token') || 
			!session.hasOwnProperty('email') ||
			!session.hasOwnProperty('name')  ){

			req.session = null
			res.redirect('/');
		} else {

			async.waterfall([
					function( next ) {

						db.UserModel.findUserByEmail( session.email, function( err, user_data ) {

							next( err, session, user_data );
						} )
					}, function( session_data, user_data, next ) {

						db.AuthTokenModel.invalidateToken( user_data._id, session_data.token, function( err ) {

							next( err, session_data );
						})
					}
				], function(err, result){

					req.session = null
					res.redirect('/');	
				})
		}
	})

router
	.get('/login', function( req, res ) {

		res.render('login',{

		});
	})
	.post('/login', function( req, res ) {

		//res.send( req.body );return;

		let email = req.body.lg_email;
		let password = req.body.lg_password;

		let error = [];

		let email_regex = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    	if ( !email_regex.test(String(email).toLowerCase()) ) {

    		error.push("Invalid email");
    	}

    	if( password.length < 6 ) {

    		error.push("Password is less than 6 characters");
    	}

    	if( error.length ) {

	    	res.render('login',{

				error: error
			});		

			return;
		}

		async.waterfall([

				function( next ) {

					db.UserModel.validateUser( email, password, next )
				}, function( user_data, next ) {

					if( !user_data ) {

						return next({message: "Invalid user details"})
					}else{

						db.AuthTokenModel.generateToken( user_data._id, function( err, token_data ) {

							next( err, user_data, token_data );
						} )
					}
				}
			],function(err, user_data, token_data){

				if( err ) {

					res.render('login',{

						error: err.message
					});		
				} else {

					req.session = {
						email: user_data.email,
						name: user_data.name,
						token: token_data.token
					}

					res.redirect('/')
				}
			})
	});

router
	.get('/register', function( req, res ) {

		res.render('register',{

		});
	})
	.post('/register', function( req, res ) {

		//res.send( req.body );return;

		let email = req.body.reg_email;
		let password = req.body.reg_password;
		let password_confirm = req.body.reg_password_confirm;
		let fullname = req.body.reg_fullname;
		let agree = req.body.reg_agree;

		let error = [];

		let email_regex = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    	if ( !email_regex.test(String(email).toLowerCase()) ) {

    		error.push("Invalid email");
    	}

    	if( password.length < 6 ) {

    		error.push("Password is less than 6 characters");
    	}

    	if( password !== password_confirm ) {

    		error.push("Confirm password is different than password");
    	}

    	if( !fullname ) {

    		error.push("Please enter your fullname");	
    	}

    	if( agree != "on" ) {

    		error.push("Please check agree terms");
    	}
    	
    	if( error.length ) {

	    	res.render('register',{

				error: error
			});		

			return;
		}

		async.waterfall([
				function( next ) {

					db.UserModel.insertUser( fullname, email, password, next );
				}
			], function(err, result){

				if( err ) {

					res.render('register',{

						error: error
					});		
				} else {

					res.render('register',{

						success: "Registration sucess, Please login"
					});
				}
			});
	})

router
	.get('/forgotpassword', function( req, res ) {

		res.render('forgotpassword',{

		});
	})
	.post('/forgotpassword', function( req, res ) {

		//res.send( req.body );return;		

		let email = req.body.fp_email;

		let error = [];

		let email_regex = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    	if ( !email_regex.test(String(email).toLowerCase()) ) {

    		error.push("Invalid email");
    	}

    	if( error.length ) {

	    	res.render('login',{

				error: error
			});		

			return;
		}

		async.waterfall([

				function( next ) {

					db.UserModel.findUserByEmail( email, next );
				}, function( user_data, next ) {

					if( !user_data ) {

						return next({message: "Invalid user details"})
					}else{

						db.AuthTokenModel.generateToken( user_data._id, function( err, token_data ) {

							next( err, user_data, token_data );
						} )						
					}
				}
			],function(err, user_data, token_data){

				if( err ) {

					res.render('login',{

						error: err
					});		
				} else {

					let nodemailer = require('nodemailer');
					let resetUrl = 'http://'+config.host+':'+config.port+'/resetpassword?email='+user_data.email+'&token='+token_data.token;

					async.waterfall([

							function( next ) {

								nodemailer.createTestAccount(next)
							}, function( account, next ) {

								let transporter = nodemailer.createTransport({

						            host: account.smtp.host,
						            port: account.smtp.port,
						            secure: account.smtp.secure,
						            auth: {
						                user: account.user,
						                pass: account.pass
						            },
						            logger: true,
						            debug: false // include SMTP traffic in the logs
						        },
						        {
						            from: 'Authentication Demo <noreply@authdemo.in>',
						            headers: {						            
						            }
						        });

						        let mailOptions = {
									to: user_data.email,
									subject: '[Authentication Demo] Forgot Password',
									html: 'Hi,<br><br>Please <a href="'+resetUrl+'">click here</a> to reset your password.<br><br>Thanks'
								};

								transporter.sendMail(mailOptions, function( err, info ) {

									console.log( err );
									console.log( info );

									transporter.close();
									next( err, info );
								} );
							}
						], function( err, result ){

							res.render('forgotpassword',{

								success: "An email has been sent to your email id to reset the password.<br>"+
										"You can also <a href='"+resetUrl+"'>click here</a> to reset the password (For Demo only)"
							});
						})
				}
			})
	});

router
	.get('/resetpassword', function( req, res ) {

		let email = req.query.email;
		let token = req.query.token;

		let error = [];

		let email_regex = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
		if ( !email_regex.test(String(email).toLowerCase()) ) {

			error.push("Invalid email");
		}

		if( error.length ) {

	    	res.send("Invalid usage");
			return;
		}

		async.waterfall([
			function( next ) {

				db.UserModel.findUserByEmail( email, next )
			}, function( user_data, next ) {

				db.AuthTokenModel.verifyToken( user_data._id, token, function( err, token_data ) {

					next( err, user_data );
				})
			}
		], function(err, user_data){

			if( err ) {

		    	res.send("Invalid usage");
				return;
			}

			res.render('resetpassword',{

				email: user_data.email
			});
		})
	})
	.post('/resetpassword', function( req, res ) {

		let req_email = req.query.email;
		let req_token = req.query.token;

		let email = req.body.rp_email;
		let password = req.body.rp_password;
		let password_confirm = req.body.rp_password_confirm;

		let error = [];

		if( req_email != email ) {

    		error.push("Invalid Usage");
    		res.render('register',{

				error: error
			});		

			return;
    	}

		let email_regex = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    	if ( !email_regex.test(String(email).toLowerCase()) ) {

    		error.push("Invalid email");
    	}

    	if( password.length < 6 ) {

    		error.push("Password is less than 6 characters");
    	}

    	if( password !== password_confirm ) {

    		error.push("Confirm password is different than password");
    	}

    	if( error.length ) {

	    	res.render('register',{

				error: error
			});		

			return;
		}

		async.waterfall([
				function( next ) {

					db.UserModel.findUserByEmail( email, next )
				}, function( user_data, next ) {

					db.AuthTokenModel.verifyToken( user_data._id, req_token, function( err, token_data ) {

						next( err, user_data );
					})
				}, function( user_data, next ) {

					db.AuthTokenModel.invalidateToken( user_data._id, req_token, next );
				}, function( token_data, next ){

					db.UserModel.resetPassword( email, password, next );
				}
			], function(err, result){

				if( err ) {

					res.render('resetpassword',{

						error: err.message
					});	
				} else {

					res.render('resetpassword',{

						success: "Password updated successfully.<br>"+
								"Please <a href='/login'>click here</a> to login."
					});
				}
			});

		//res.send(req.body)
	});

module.exports = router;