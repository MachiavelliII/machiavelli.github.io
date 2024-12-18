window.onload = function() {
    const rssUrl = 'https://medium.com/feed/@machiavellli'; // Replace with the Medium user's RSS feed URL
    const container = document.getElementById('rss-container'); // The element where the RSS feed will be inserted

    // Fetch the RSS feed from Medium
    fetch(rssUrl)
        .then(response => response.text()) // Get the feed content
        .then(str => new window.DOMParser().parseFromString(str, "text/xml")) // Parse as XML
        .then(data => {
            const items = data.querySelectorAll('item'); // Get all items (blog posts)
            items.forEach(item => {
                const title = item.querySelector('title').textContent;
                const link = item.querySelector('link').textContent;
                const description = item.querySelector('description').textContent;

                // Create an HTML structure for each post
                const entry = document.createElement('div');
                entry.classList.add('rss-entry');
                entry.innerHTML = `
                    <h3><a href="${link}" target="_blank">${title}</a></h3>
                    <p>${description}</p>
                `;
                container.appendChild(entry); // Append the post to the container
            });
        })
        .catch(error => console.error('Error fetching the RSS feed:', error));
};
