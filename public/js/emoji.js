var selection = -1;

function selectMessage(id) {
    selection = id;
    console.log("Selected: " + selection);
}

function selectEmoji(id) {
    if(selection <= 0) {
        console.log("Invalid Selection: " + selection);
        return;
    }

    console.log("Reacting to " + selection + " with " + id);
    document.location.href = `/react?message=${selection}&emoji=${id}`;
}