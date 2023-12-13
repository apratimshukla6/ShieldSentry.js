// index.js

const fs = require('fs');
const path = require('path');

class ShieldSentry {
    constructor() {
        const specificationPath = path.join(__dirname, 'specifications.json');
        this.specification = JSON.parse(fs.readFileSync(specificationPath, 'utf8'));
        this.roles = this.specification.accessControl.roles;
        this.permissions = this.specification.accessControl.permissions;
        this.rateLimiting = this.specification.apiRateLimiting;
        this.userRequests = {}; // Tracks user requests
    }

    validate(inputType, value) {
        const rules = this.specification.inputTypes[inputType];
        if ('maxLength' in rules && value.length > rules.maxLength) {
            return false;
        }
        if ('regex' in rules && !new RegExp(rules.regex).test(value)) {
            return false;
        }
        if (inputType === 'numeric' && (isNaN(value) || value < rules.min || value > rules.max)) {
            return false;
        }
        return true;
    }

    htmlEscape(value) {
        const escapeChars = this.specification.sanitization['HTML'].escapeCharacters;
        return Object.entries(escapeChars).reduce((acc, [char, escapedChar]) => {
            const regex = new RegExp(char, 'g');
            return acc.replace(regex, escapedChar);
        }, value);
    }

    sqlEscape(value) {
        const escapeChars = this.specification.sanitization['SQL'].escapeCharacters;
        return Object.entries(escapeChars).reduce((acc, [char, escapedChar]) => {
            const regex = new RegExp(char, 'g');
            return acc.replace(regex, escapedChar);
        }, value);
    }

    sanitize(context, value) {
        switch (context) {
            case 'HTML':
                return this.htmlEscape(value);
            case 'SQL':
                return this.sqlEscape(value);
            default:
                // Default behavior is to not sanitize, but you could log an error or handle as needed
                return value;
        }
    }

    handleError(errorType) {
        const error = this.specification.errors[errorType];
        console.error(`Error ${error.code}: ${error.message}`);
    }

    hasPermission(userRole, action) {
        if (!this.roles.includes(userRole)) {
            return false;
        }

        const allowedActions = this.permissions[userRole];
        return allowedActions.includes('all') || allowedActions.includes(action);
    }

    isRateLimited(userId) {
        const currentTime = Date.now();
        const userRequest = this.userRequests[userId];

        if (!userRequest) {
            // First request from this user
            this.userRequests[userId] = { count: 1, lastRequestTime: currentTime, quotaUsed: 1 };
            return false;
        }

        if (userRequest.quotaUsed >= this.rateLimiting.quotaThreshold) {
            // Quota exceeded
            return true;
        }

        if (currentTime - userRequest.lastRequestTime > 60000) {
            // Reset count after 1 minute
            userRequest.count = 1;
            userRequest.lastRequestTime = currentTime;
        } else if (userRequest.count >= this.rateLimiting.maxRequestsPerMinute) {
            // Rate limit exceeded
            return true;
        } else {
            // Increment request count
            userRequest.count++;
        }

        // Increment quota used
        userRequest.quotaUsed++;

        return false;
    }
}

module.exports = ShieldSentry;