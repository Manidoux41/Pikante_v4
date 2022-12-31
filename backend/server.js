"use strict";
/**
 * 
 * pour le site en production utiliser :
 * const https = require("https"); 
 * ce réferer à OpenSSL pour optenir un certificat SSL
 * 
 */ 

import http from 'http';
import  app from './app.js'
/****************return of a valid port provided in the form of a number or a string**************/
const normalizePort = (val) => {
  const port = parseInt(val, 10);
  if (isNaN(port)) {
    return val;
  }
  if (port >= 0) {
    return port;
  }
  return false;
};
const port = normalizePort(process.env.PORT || process.env.SERVER_CONNECT);//return port valid//errorHandler:look error
app.set("port", port);
/*************************error search and management then save in the server**********************/
const errorHandler = (error) => {
  if (error.syscall !== "listen") {
    throw error;
  }
  const address = server.address();
  const bind =
    typeof address === "string" ? "pipe " + address : "port: " + port;
  switch (error.code) {
    case "EACCES":
      console.error(bind + " requires elevated privileges.");
      process.exit(1);
      break;
    case "EADDRINUSE":
      console.error(bind + " is already in use.");
      process.exit(1);
      break;
    default:
      throw error;
  }
};
/**
 * createServer() react to incoming requests and receive as arguments: the object requête/responce/next
 * production = const server = https.createServer(app);
 */
const server = http.createServer(app);
//registered event listener logging the port or channel the server is running on
server.on("error", errorHandler);
server.on("listening", () => {
  const address = server.address();
  const bind = typeof address === "string" ? "pipe " + address : "port " + port;
  console.log("Listening on " + bind);
});
server.listen(port);
