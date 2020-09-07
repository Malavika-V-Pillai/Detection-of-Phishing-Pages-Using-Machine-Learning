console.log("Back Ground");

var getJSON = function(url, callback) {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', url, true);
    xhr.responseType = 'json';
    xhr.onload = function() {
        callback(null, xhr.response);
      
    };
    xhr.send();
}; 

function buttonClicked(tab){
    // console.log(tab);
    console.log(tab.url)
    
    console.log("Sending url");
    getJSON("http://127.0.0.1:8000/api/"+tab.url,
        function(err, data) {
            var json = JSON.stringify(data);
            console.log(JSON.parse(json).output);
            let msg ={
                txt:JSON.parse(json).output
            }
            chrome.tabs.sendMessage(tab.id,msg);
            // chrome.browserAction.setIcon({ path: {"50":"48r.png"} });
            if(msg.txt === "Legitimate Page"){  
                console.log("L icon setting")
                chrome.browserAction.setIcon({path: "48g.png"} );
            }
            else if(msg.txt === "Phishing Page"){   
                chrome.browserAction.setIcon({path: "48r.png" });
            }

            
        });
    
    console.log("stop");
    // chrome.tabs.sendMessage(tab.id,msg);
    // chrome.notifications.create({
    //     "type":"basic",
    //     "iconUrl":"icons/48.png",
    //     "title":"my notification",
    //     "message":msg.txt
    // });
}
chrome.browserAction.onClicked.addListener(buttonClicked);