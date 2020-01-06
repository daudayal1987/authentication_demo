const async = require('async');

let db = require('../db.js');

export async function validateLogin(req){

    return new Promise((resolve, reject)=>{
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

                    next( err, user_data.id );
                })
            }
        ], function(err, user_id){

            if(err){

                reject(err)
            } else {

                resolve(user_id);
            }
        }); 
    });
}

export async function fetchUserData(user_id){

    return new Promise((resolve, reject)=>{

        let query = db.UserModel.findOne({
            _id: user_id
        });

        query.then(function(doc){

            resolve(doc);
        });
    })
}

export async function updateUserProfile(user_id, full_name, gender, dob){

    return new Promise((resolve, reject)=>{

        let query = db.UserModel.findOneAndUpdate({
            _id: user_id
        },{
            $set:{
                name: full_name,
                gender: gender,
                dob: dob
            }
        },{
            new: true,
            useFindAndModify: false
        });

        query.then(function(doc){

            resolve(doc);
        })
    });
}