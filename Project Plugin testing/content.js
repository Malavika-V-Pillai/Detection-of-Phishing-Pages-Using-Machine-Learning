document.body.style.border = "5px solid red";   //To check plugin is active
console.log("content scripting...");			//To check the console

// To seek to permission for notification
if (!("Notification" in window)){
	alert("This browser does not support system notifications");
}
else if (Notification.permission === "granted"){
	console.log("granted");
}
else if (Notification.permission !== 'denied'){
	Notification.requestPermission();
}

// Listener to accepted result
chrome.runtime.onMessage.addListener(gotMessage);

function gotMessage(message, sender, sendRepsonse){
	// For function test
	console.log(message.txt);
    function notifyMe() {

		if (!("Notification" in window)){
	    	alert("This browser does not support system notifications");
	  	}
		else if (Notification.permission === "granted") {
			notify();
		}
		else if (Notification.permission !== 'denied'){
	    	Notification.requestPermission(function (permission){
	      		if (permission === "granted") {
	       		 	notify();
	      		}
	    	});
	  	}
	  
	  	function notify() {

	  		if(message.txt === "Legitimate Page"){	
		    	var notification = new Notification('Message from Phishy', {
		      		icon: "https://i.ibb.co/vmPFdZt/48g.png",
		      		body: message.txt,
		    	});
		    }
		    else if(message.txt === "Phishing Page"){	
		    	var notification = new Notification('Message from Phishy', {
		      		icon: "https://i.ibb.co/7Nqh4VK/48r.png",
		      		body: message.txt,
		    	});
		    }
		    else {	
		    	var notification = new Notification('Message from Phishy', {
		      		icon: "https://i.ibb.co/XVNnJ67/48.png",
		      		body: message.txt,
		    	});
		    }
	    	

	    	// notification.onclick = function () {
	     // 		window.open("http://www.cybermonster.tech");      
	    	// };


	    	// Timeout for the notification
	    	setTimeout(notification.close.bind(notification), 50000); 
	  	}
	}	
	notifyMe();
}