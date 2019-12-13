const path = require('path');

module.exports = {
    configureWebpack: {
        entry: {
            app: './gui/app.js'
        }
    },
    outputDir: path.resolve(__dirname, 'gui-dist'),
}