require([
    "jquery",
    "splunkjs/mvc",
    "splunkjs/mvc/simplexml/ready!"
], function($, mvc) {
    console.log("Feedback script loaded");
    
    var apiHost = window.location.hostname || "127.0.0.1";
    var apiBaseUrl = "http://" + apiHost + ":8080/api/v1";
    
    function getApiKey() {
        var key = sessionStorage.getItem("redforesight_api_key");
        if (!key) {
            key = prompt("Enter RedForesight API Key:");
            if (key) {
                sessionStorage.setItem("redforesight_api_key", key);
            }
        }
        return key || "";
    }
    
    // Live episode count polling
    function fetchHealth() {
        $.ajax({
            url: apiBaseUrl + "/health",
            type: "GET",
            headers: {
                "X-API-Key": getApiKey()
            },
            success: function(data) {
                $("#live_episode_count").text(data.episode_count || 0);
            },
            error: function() {
                console.log("Failed to fetch episode count");
            }
        });
    }
    
    // Initial fetch and poll
    setTimeout(fetchHealth, 1000);
    setInterval(fetchHealth, 5000);

    // Button click intercept
    $(document).on("click", "#submitFeedbackBtn", function(e) {
        e.preventDefault();
        
        var episodeId = $("#episode_id").val();
        var techniqueId = $("#technique_id").val();
        var outcome = $("#outcome").val() === "true";
        
        if (!episodeId) {
            alert("Please enter an Episode ID");
            return;
        }

        var payload = {
            episode_id: episodeId,
            confirmed_technique_id: techniqueId,
            outcome_confirmed: outcome
        };
        
        $.ajax({
            url: apiBaseUrl + "/feedback",
            type: "POST",
            contentType: "application/json",
            headers: {
                "X-API-Key": getApiKey()
            },
            data: JSON.stringify(payload),
            success: function(response) {
                alert("Feedback saved successfully!");
                fetchHealth(); // Update count immediately
            },
            error: function(err) {
                alert("Error saving feedback. Make sure FastAPI is running.");
            }
        });
    });
});
