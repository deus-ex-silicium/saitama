Java.perform(function () {
    // Function to hook is defined here
    console.log('sent: Hello World');
    
    setInterval(function(){ send('received: Hello World'); }, 7000);
});