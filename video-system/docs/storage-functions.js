function createStorageCapacityHTML(sectionId, storageTextId, storageUsedId, storageDetailsId) {
    var html = "<div class=\"storage-info\">";
    html += "<div style=\"display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;\">";
    html += "<span><strong>💾 Storage Status</strong></span>";
    html += "<div style=\"text-align: right;\">";
    html += "<span id=\"" + storageTextId + "\">Loading...</span>";
    html += "<div style=\"text-align: right; margin-top: 3px;\">";
    html += "<button class=\"quota-btn\" onclick=\"openQuotaConfig('" + sectionId + "')\">💽 Disk quota upload limit</button>";
    html += "</div></div></div>";
    html += "<div class=\"storage-bar\">";
    html += "<div class=\"storage-used\" id=\"" + storageUsedId + "\" style=\"width: 0%\"></div>";
    html += "</div>";
    html += "<div class=\"storage-details-vertical\">";
    html += "<div class=\"storage-detail-item storage-available\">";
    html += "<span>Available:</span><span id=\"storage-available-" + sectionId + "\">--</span>";
    html += "</div>";
    html += "<div class=\"storage-detail-item storage-reserve\">";
    html += "<span>Reserve:</span><span id=\"storage-reserve-" + sectionId + "\">--</span>";
    html += "</div>";
    html += "<div class=\"storage-detail-item storage-upload-limit\">";
    html += "<span>Upload limit:</span><span id=\"storage-upload-" + sectionId + "\">--</span>";
    html += "</div></div>";
    html += "<span id=\"" + storageDetailsId + "\" style=\"display: none;\">Checking storage...</span>";
    html += "</div>";
    return html;
}

function replaceAllStorageSections() {
    console.log("Starting storage section replacement...");
    var sections = [
        {container: "video-content", sectionId: "video", textId: "storage-text-video", usedId: "storage-used-video", detailsId: "storage-details-video"},
        {container: "file-content", sectionId: "files", textId: "storage-text-files", usedId: "storage-used-files", detailsId: "storage-details-files"},
        {container: "upload-content", sectionId: "upload", textId: "storage-text", usedId: "storage-used", detailsId: "storage-details"},
        {container: "general-upload-content", sectionId: "general", textId: "storage-text-general", usedId: "storage-used-general", detailsId: "storage-details-general"},
        {container: "download-content", sectionId: "downloads", textId: "storage-text-downloads", usedId: "storage-used-downloads", detailsId: "storage-details-downloads"}
    ];
    
    for (var i = 0; i < sections.length; i++) {
        var section = sections[i];
        var container = document.getElementById(section.container);
        if (container) {
            var storageInfoDiv = container.querySelector(".storage-info");
            if (storageInfoDiv) {
                storageInfoDiv.outerHTML = createStorageCapacityHTML(section.sectionId, section.textId, section.usedId, section.detailsId);
            }
        }
    }
    
    setInterval(updateAllStorageDetails, 1000);
}

function updateAllStorageDetails() {
    var sections = [
        {id: "video", detailsId: "storage-details-video"},
        {id: "files", detailsId: "storage-details-files"}, 
        {id: "upload", detailsId: "storage-details"},
        {id: "general", detailsId: "storage-details-general"},
        {id: "downloads", detailsId: "storage-details-downloads"}
    ];
    
    for (var i = 0; i < sections.length; i++) {
        var section = sections[i];
        var detailsEl = document.getElementById(section.detailsId);
        if (detailsEl && detailsEl.textContent && detailsEl.textContent !== "Checking storage...") {
            updateStorageDetails(section.id, detailsEl.textContent);
        }
    }
}

function updateStorageDetails(sectionId, storageText) {
    var parts = storageText.split(" • ");
    for (var i = 0; i < parts.length; i++) {
        var trimmed = parts[i].trim();
        if (trimmed.indexOf("Available:") !== -1) {
            var value = trimmed.replace("Available: ", "");
            var el = document.getElementById("storage-available-" + sectionId);
            if (el) el.textContent = value;
        } else if (trimmed.indexOf("Reserve:") !== -1) {
            var value = trimmed.replace("Reserve: ", "");
            var el = document.getElementById("storage-reserve-" + sectionId);
            if (el) el.textContent = value;
        } else if (trimmed.indexOf("Upload limit:") !== -1) {
            var value = trimmed.replace("Upload limit: ", "");
            var el = document.getElementById("storage-upload-" + sectionId);
            if (el) el.textContent = value;
        }
    }
}

function openQuotaConfig(section) {
    alert("Opening quota configuration for: " + (section || "default"));
}

document.addEventListener("DOMContentLoaded", function() {
    setTimeout(replaceAllStorageSections, 500);
});