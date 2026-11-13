export default function handler(req, res) {
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Vercel Test - Graphics</title>
      <style>
        body {
          font-family: Arial, sans-serif;
          text-align: center;
          padding: 50px;
          background-color: #f0f0f0;
        }
        h1 { color: #0000EE; }
        img { border: 5px solid #333; border-radius: 10px; }
      </style>
    </head>
    <body>
      <h1>It Works!</h1>
      <img src="https://placehold.co/300x150" alt="Test Graphic" />
      <p>Your Vercel connection is working correctly. You should see this image and text.</p>
    </body>
    </html>
  `;

  res.setHeader('Content-Type', 'text/html');
  res.status(200).send(html);
}
