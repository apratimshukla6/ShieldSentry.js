// index.js

const fs = require('fs');
const path = require('path');

class ShieldSentry {
    constructor() {
        const specificationPath = path.join(__dirname, 'specifications.json');
        this.specification = JSON.parse(fs.readFileSync(specificationPath, 'utf8'));
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
}

module.exports = ShieldSentry;