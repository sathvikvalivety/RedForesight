require([
    "jquery",
    "splunkjs/mvc",
    "splunkjs/mvc/simplexml/ready!"
], function($, mvc) {
    console.log("Feedback script loaded");
    
    // Live episode count polling
    function fetchHealth() {
        $.get("http://127.0.0.1:8080/api/v1/health")
         .done(function(data) {
             $("#live_episode_count").text(data.episode_count || 0);
         })
         .fail(function() {
             console.log("Failed to fetch episode count");
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
            url: "http://127.0.0.1:8080/api/v1/feedback",
            type: "POST",
            contentType: "application/json",
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
