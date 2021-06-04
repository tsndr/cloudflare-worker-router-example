const validator = require('validator')
const bcrypt = require('bcryptjs')
const jwt = require('../libs/jwt')

module.exports = new class {
    async register(req, res) {

        // Validation
        const errors = {}
        if (!req.body.salutation)
            errors.salutation = 'error_required'
        else if (!['mr', 'ms'].includes(req.body.salutation))
            errors.salutation = 'error_invalid_format'
        if (!req.body.first_name)
            errors.first_name = 'error_required'
        if (!req.body.last_name)
            errors.last_name = 'error_required'
        if (!req.body.email)
            errors.email = 'error_required'
        else if (!validator.isEmail(req.body.email))
            errors.email = 'error_invalid_email'
        if (!req.body.password)
            errors.password = 'error_required'
        else if (req.body.password.length < 8)
            errors.password = 'error_invalid_min_string'
        if (Object.keys(errors).length) {
            res.status = 422
            res.body = { errors }
            return
        }

        // Check if user already exists
        if (await USER.get(req.body.email) !== null) {
            res.status = 400
            res.body = {
                errors: {
                    email: 'error_email_taken'
                }
            }
            return
        }

        // Create user
        await USER.put(req.body.email, JSON.stringify({
            salutation: req.body.salutation,
            first_name: req.body.first_name,
            last_name: req.body.last_name,
            password: bcrypt.hashSync(req.body.password, 10),
            created: (new Date()).toISOString(),
            updated: (new Date()).toISOString()
        }))

        res.status = 204
    }

    async login(req, res) {

        // Validation
        const errors = {}
        if (!req.body.email)
            errors.email = 'error_required'
        else if (!validator.isEmail(req.body.email))
            errors.email = 'error_invalid_email'
        if (!req.body.password)
            errors.password = 'error_required'
        if (Object.keys(errors).length) {
            res.status = 422
            res.body = { errors }
            return
        }

        // Get user from KV
        const user = JSON.parse(await USER.get(req.body.email))

        // If user doesn't exist
        if (user === null) {
            res.status = 400
            res.body = {
                errors: {
                    email: 'error_email_password_wrong'
                }
            }
            return
        }

        // If user is blocked
        if (user.disabled) {
            res.status = 400
            res.body = {
                errors: {
                    email: 'error_account_suspended'
                }
            }
            return
        }

        // If password wrong
        if (!bcrypt.compareSync(req.body.password, user.password)) {
            user.failed_logins = (user.failed_logins || 0) + 1
            if (user.failed_logins >= 3) {
                user.failed_logins = undefined
                user.disabled = true
            }
            user.save()
            res.status = 400
            res.body = {
                errors: {
                    email: 'error_email_password_wrong' // We know it's the password, but we're not leaking this info ;)
                }
            }
            return
        }

        // Reset failed login attempts
        user.failed_logins = undefined

        // Save user data
        await USER.put(req.body.email, JSON.stringify({
            ...user,
            updated: (new Date()).toISOString()
        }))

        res.status = 200
        res.body = {
            token: await jwt.sign({
                salutation: user.salutation,
                first_name: user.first_name,
                last_name: user.last_name,
                email: req.body.email
            }, `${JWT_SECRET}.${req.body.email}.${user.password}`, 'HS512') // Adding E-Mail address and password hash to jwt secret to have the token invalidate once one of those things change
        }
    }

    async get(req, res) {
        // Return user data (since this endpoint uses the token middleware the userdata is already available to us through the req object)
        res.body = {
            data: {
                salutation: req.auth.user.salutation,
                first_name: req.auth.user.first_name,
                last_name: req.auth.user.last_name,
                email: req.auth.user.email
            }
        }
    }

    async update(req, res) {

        // Validation
        const errors = {}
        if (req.body.salutation && !['mr', 'ms'].includes(req.body.salutation))
            errors.salutation = 'error_invalid_format'
        if (req.body.email && !validator.isEmail(req.body.email))
            errors.email = 'error_invalid_email'
        if (req.body.password && req.body.password.length < 8)
            errors.password = 'error_invalid_min_string'
        if (Object.keys(errors).length) {
            res.status = 422
            res.body = { errors }
            return
        }
        
        // Check if E-Mail address is already taken
        if (req.body.email && req.body.email != req.auth.user.email) {
            if (await USER.get(req.body.email) !== null) {
                res.status = 400
                res.body = {
                    errors: {
                        email: 'error_email_taken'
                    }
                }
                return
            }
            
            // Since we're using the E-Mail address as our key, we have to delete the user and create it again with the new E-Mail address
            await USER.delete(req.auth.email)
            req.auth.email = req.body.email
        }

        // Setting data by hand if they were part of the request to prevent stuff we don't want from getting in our KV store
        if (req.body.salutation) {
            req.auth.user.salutation = req.body.salutation
        }
        if (req.body.first_name) {
            req.auth.user.first_name = req.body.first_name
        }
        if (req.body.last_name) {
            req.auth.user.last_name = req.body.last_name
        }
        if (req.body.password) {
            // Hashing password if a new one was given
            req.auth.user.password = bcrypt.hashSync(req.body.password, 10)
        }

        // Save user data to KV store
        await USER.put(req.auth.email, JSON.stringify({
            ...req.auth.user,
            updated: (new Date()).toISOString()
        }))

        res.status = 204
    }

    async delete(req, res) {
        await USER.delete(req.auth.email)
        res.status = 204
    }
}