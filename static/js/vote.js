
const maxCredits = Number(document.getElementById("numCredits").innerHTML);
console.log("maximum credits: " + maxCredits);

let tbody = document.getElementById("voteTable");
let i=0, numCandidates =0;
while(tbody.getElementsByTagName('tr') [i++]) numCandidates++;
console.log("number of candidates: " + numCandidates);

document.getElementsByClassName('field').onchange = function() {
    console.log('change')
    let field = document.getElementsByClassName('field').value;
    console.log(field);
}

function change(field) {
    let votes = document.getElementById(field);
    console.log(votes.value)

    let CNCL = maxCredits; //credits not current left

    for (let i=0; i<numCandidates; i++) {
        loopedField = "field"+ String(i) + "_votes";
        if (field != loopedField) {
            CNCL -= document.getElementById(loopedField).value**2;
        }
    }

    let numMaxVotes = Math.round(Math.sqrt(CNCL) - 0.5);
    votes.max = Number(numMaxVotes);
    votes.min = Number(-1 * numMaxVotes);

    console.log('max ' + votes.max);
    console.log('min ' + votes.min);
    console.log('val ' + votes.value);
    console.log('CNCL ' + CNCL);


    if (Number(votes.value) > votes.max) {
        votes.value = votes.max;
    }
    else if (Number(votes.value) < votes.min) {
        votes.value = votes.min;
    }

    let credits = votes.value**2;
    let creditsHTML = document.getElementById(field.slice(0, -6) + '_credits');
    creditsHTML.innerHTML = credits;

    let creditsLeftHTML = document.getElementById("numCredits");
    creditsLeftHTML.innerHTML = CNCL - credits
}
