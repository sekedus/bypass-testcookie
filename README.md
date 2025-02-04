# Bypass testcookie

This project is designed to bypass protection mechanisms implemented by [testcookie-nginx-module][testcookie].

<!-- It provides an Express-based API to retrieve content from protected websites, handling cookie challenges automatically. -->

Works for free hosting providers that use the MyOwnFreeHost service.

<!-- ## Features

- Bypasses [testcookie-nginx-module][testcookie] protection
- Uses `axios` for HTTP requests with SSL handling
- Parses and evaluates AES-based JavaScript challenges
- Stores cookies for future requests
- Implements CORS headers for cross-origin access -->

## Installation

Ensure you have [Node.js](https://nodejs.org/) installed, then clone the repository and install dependencies:

1. Open your terminal and clone this repository:

    ```bash
    git clone https://github.com/sekedus/bypass-testcookie.git
    ```

2. Change to the cloned directory:

    ```bash
    cd bypass-testcookie
    ```

3. Install the required dependencies:

    ```bash
    npm install
    ```

## Usage

### Start the Server

```sh
npm start
```
The server will run on `http://localhost:3000` by default.

### API Endpoints

```
GET /<url>
```
- Replace `<url>` with the full target URL (e.g., `http://example.com`).
- The server will attempt to fetch the page, handle the protection mechanism, and return the content.

Example:
```sh
curl "http://localhost:3000/http://protected-site.com"
```

### Response Format

If the requested page is an HTML page, the server returns a JSON response in the following format:
```jsonc
{
  "link": "final_url_after_redirection",
  "testcookie_cache": false, // true or false
  "headers": { "content-type": "text/html; charset=UTF-8" },
  "body": "<html>...</html>"
}
```
For non-HTML content, the server responds with the raw data and appropriate `Content-Type`.

<!-- ## Project Structure

```
.
├── api
│   ├── server.js               # Main Express server
│   ├── lib/aes.js              # JavaScript challenge decryption
│   ├── lib/regexp-top-level-domain.js # TLD validation regex
│   ├── package.json            # Project metadata & dependencies
│   ├── README.md               # Project documentation
``` -->

<!-- ## Dependencies

- [Express](https://expressjs.com/)
- [Axios](https://axios-http.com/)
- [JSDOM](https://github.com/jsdom/jsdom)
- [User-Agents](https://www.npmjs.com/package/user-agents)
- [Express-Rate-Limit](https://www.npmjs.com/package/express-rate-limit) -->

## Credits

- [bypass-testcookie-php](https://github.com/yucho123987/bypass-testcookie-php)
- [CORS Anywhere](https://github.com/Rob--W/cors-anywhere)

## License
This project is licensed under the **GPL-3.0** License.

[testcookie]: https://github.com/kyprizel/testcookie-nginx-module
