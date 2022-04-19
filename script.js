// @File: scripts/script.js

setTimeout(function() {
    Java.perform(function() {

        // We are loading the class here
        var Rfunc = Java.use("a.a.a.a.a");

        // Whenever a.a.a.a.a.R() is called, the below code is executed
        Rfunc.R.implementation = function() {
            // Capture the return value of R function
            let retval = this.R();
            // Printing the value we got from this function
            console.log("Original return value = ", retval);
            // Toggle the return value to make sure it doesn't enter the if loop
            return !retval
        }
    })
}, 10);