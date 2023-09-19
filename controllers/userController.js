const User = require('../models/User');
const bcrypt = require('bcrypt');



// rendering home page
module.exports.homepage = function (req, res) {
    if (req.isAuthenticated()) {
        return res.render('home');

    }
    return res.redirect('/login');
}
// Rendering signup  page
module.exports.signupPage = function (req, res) {
    if (req.isAuthenticated()) {
        return res.redirect('/home');
    }
    return res.render('signup');
}

// Rendering login page
module.exports.loginPage = function (req, res) {
    if (req.isAuthenticated()) {
        return res.redirect('/home');
    }
    return res.render('login');
}


// rendering reset page
module.exports.resetPage = function (req, res) {
    return res.render('resetPassword');
}

// signup functionality
module.exports.signup = async (req, res) => {
    try {
        const { name, email, password, confirm_Password } = req.body;

        // check password and confirm password id match or not
        if (password !== confirm_Password) {
            req.flash('error', 'Password and Confirm Password does not match');
            return res.redirect('/');
        }

        // check if user is exist already in database  
        const existUser = await User.findOne({ email });



        if (existUser) {
            req.flash('error', 'User exist already');
            return res.redirect('/')
        }

        const plaintextPassword = password;
        const saltRounds = 10;

        const hash = await bcrypt.hash(plaintextPassword, saltRounds);

        const user = await User.create({
            name: name,
            email: email,
            password: hash
        });
        req.flash('success', 'User sign-up Successfully');
        return res.redirect('/login');



    } catch (error) {


        console.log('Something went wrong');

    }
}


// signIn functionality

module.exports.signin = async (req, res) => {
    req.flash('success', 'User logged in Successfully')
    return res.redirect('/home');
}



// password reset functionality
module.exports.reset = async (req, res) => {
    const { email, oldpassword, newpassword } = req.body
    console.log(newpassword);

    const user = await User.findOne({ email });
    if (!user) {
        req.flash('error', "Email or Password is not correct");
        return res.redirect('/reset');
    }
    const passwordMatches = await bcrypt.compare(oldpassword, user.password);
    if (!passwordMatches) {
        req.flash('error', 'Email or Password is not correct');
        return res.redirect('/reset');
    }



    const plaintextPassword = newpassword;
    const saltRounds = 10;
    const hash = await bcrypt.hash(plaintextPassword, saltRounds);
    user.password = hash;
    await user.save();
    req.flash('success', 'Password updated successfully');
    res.redirect('/login');





}



// destroy session 
module.exports.destroy = function (req, res, next) {

    req.logout(function (error) {
        if (error) {
            return next(error);
        }
        req.flash('success', 'You have logged out');
        res.redirect('/login');
    })
}