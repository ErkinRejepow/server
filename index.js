import express from "express";
import bodyParser from "body-parser";
import cors from "cors";
import mysql from "mysql2";
import fetch from "node-fetch";
import { Server } from "socket.io";
import { createRequire } from 'module';

const require = createRequire(import.meta.url);

const app = express();
const server = require('http').createServer(app);
const io = require('socket.io')(server, { cors: {origin: "*"} });
let last_timestamp;

io.on('connection', client => {
  const authHeader = client.handshake.headers.authorization;
  // client.broadcast.emit("update",{
  //   datas:[],
  //   count: null,
  //   severityCounts: {
  //     error, info, warning, total,
  //   }
  // })
  
  client.on("send_message",(data)=>{
    console.log("sentMEssage:",data);
  }) 
  if (authHeader) {
    jwt = authHeader.split(" ")[1]; // Extract the token from the "Bearer <token>" format
    setInterval(updateMessage,10000,client,jwt);
  }
});

async function updateMessage(client, jwt){
  const roleResponse = await fetch("http://192.168.8.204:8001/role", {
    method: "GET",
    headers: {
      Authorization: `Bearer ${jwt}`,
    },
  });
  const roleData = await roleResponse.json();
  if(roleData.code !== "token_not_valid"){
    rules = await roleData?.results;
    applicationCondition = rules?.map((element) => `\"${element.application}\"`).toString();
    const condition = `timestamp >= DATE_SUB(NOW(), INTERVAL 1 DAY) AND application IN (${applicationCondition})`;

    const countERRQuery = `SELECT COUNT(*) AS countERR FROM logsdb.table_kiber WHERE ${condition} AND severity="ERR"`;
    const countERRResult = await executeQuery(countERRQuery);
    const countINFOQuery = `SELECT COUNT(*) AS countINFO FROM logsdb.table_kiber WHERE ${condition} AND severity="INFO"`;
    const countINFOResult = await executeQuery(countINFOQuery);
    const countWARNINGQuery = `SELECT COUNT(*) AS countWARNING FROM logsdb.table_kiber WHERE ${condition} AND severity="WARNING"`;
    const countWARNINGResult = await executeQuery(countWARNINGQuery);

    const response = {
      total: countERRResult[0].countERR + countINFOResult[0].countINFO + countWARNINGResult[0].countWARNING,
      info: countINFOResult[0].countINFO,
      warning: countWARNINGResult[0].countWARNING,
      error: countERRResult[0].countERR
    }
    console.log("response",response);
    client.broadcast.emit("update",{
          datas:[],
          count: 10,
          severityCounts: response
        })
  }
  
}

const db = mysql.createPool({
    host: "192.168.0.254",
    // port:3306,
    user:"kiber",
    password:"kibeR@2023@Kiber",
    database:"logsdb",
    connectTimeout:25000
});

const dbLogs = mysql.createPool({
  host: "192.168.8.204",
  // port:3306,
  user:"usermysql",
  password:"P@ssw0rd12345",
  database:"Logs",
  connectTimeout:25000
});

let jwt;
let rules;
let applicationCondition

app.use(cors());
app.use(express.json());
app.use(bodyParser.urlencoded({extended:true}))

server.listen(8000, ()=>{
    console.log("Server running on port 8000");
})

app.get("/logs", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;

    const logSize = 50;
    const page = parseInt(req.query.page);
    const is_know = parseInt(req.query.is_know);
    let severity;
    const offset = (page - 1) * logSize;

    let jwt;
    let rules;
    let applicationCondition;


    if (authHeader) {
      jwt = authHeader.split(" ")[1]; // Extract the token from the "Bearer <token>" format
      
      if(is_know){
      const myusername = await fetch("http://192.168.8.204:8001/myusername", {
        method: "GET",
        headers: {
          Authorization: `Bearer ${jwt}`,
        },
      });
      let condition = "";
      const userData = await myusername.json();
      const user = userData.results[0];

      if(typeof req.query.severity !== "undefined" && req.query.severity !== ""){
        condition = condition + `AND severity="${req.query.severity}"`;
      }

      const acceptedCountQuery = `SELECT COUNT(*) AS count FROM Logs.acceptedLogs_table WHERE user_id=${user.id} ${condition}`;
      const acceptedCountResult = await executedbLogsQuery(acceptedCountQuery);

      const acceptedLogQuery = `SELECT * FROM Logs.acceptedLogs_table WHERE user_id=${user.id} ${condition} ORDER BY timestamp DESC LIMIT ${logSize} OFFSET ${offset}`;
      const acceptedLogResult = await executedbLogsQuery(acceptedLogQuery);

      const response = {
        results: acceptedLogResult.map((log)=>{
          log.is_know = 1;
          return log;
        }),
        count: acceptedCountResult[0].count,
      };
      res.send(response);
      return
    }
      
      const roleResponse = await fetch("http://192.168.8.204:8001/role", {
        method: "GET",
        headers: {
          Authorization: `Bearer ${jwt}`,
        },
      });
      const roleData = await roleResponse.json();
      rules = roleData.results;
      applicationCondition = rules?.map((element) => `\"${element.application}\"`).toString();
      let condition = `timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR) AND application IN (${applicationCondition})`;
      if(typeof req.query.severity !== "undefined" && req.query.severity !== ""){
        condition = condition + `AND severity="${req.query.severity}"`;
      }

      const countQuery = `SELECT COUNT(*) AS count FROM logsdb.table_kiber WHERE ${condition}`;
      const countResult = await executeQuery(countQuery);

      const sqlQuery = `SELECT * FROM logsdb.table_kiber WHERE ${condition} ORDER BY timestamp DESC LIMIT ${logSize} OFFSET ${offset}`;
      const logsResult = await executeQuery(sqlQuery);

      const response = {
        results: logsResult.map((log)=>{
          log.is_know = 0;
          return log;
        }),
        count: countResult[0].count,
      };
      res.send(response);
    } else {
      // Handle unauthorized access
      // res.status(401).json({ error: 'Unauthorized' });
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.put("/logs/:id", async (req, res) => {
  try {
    
    const authHeader = req.headers.authorization;

    let jwt;
    let user;

    if (authHeader) {
      jwt = authHeader.split(" ")[1]; // Extract the token from the "Bearer <token>" format
      const myusername = await fetch("http://192.168.8.204:8001/myusername", {
        method: "GET",
        headers: {
          Authorization: `Bearer ${jwt}`,
        },
      });
      const userData = await myusername.json();
      user = userData.results[0];

    const logId = parseInt(req.params.id);

    const sqlQuery = `SELECT * FROM logsdb.table_kiber WHERE id=${logId} ORDER BY timestamp DESC;`;
    const logsResult = await executeQuery(sqlQuery);

    const value = logsResult[0];
    const insertQuery = `INSERT INTO Logs.acceptedLogs_table(hostname, facility, severity, application, message, user_id) 
                          VALUES ("${value.hostname}","${value.facility}","${value.severity}","${value.application}","${value.message}","${user.id}");`;
    const insertResult = await executedbLogsQuery(insertQuery);

    const deleteQuery = `DELETE FROM logsdb.table_kiber WHERE id=${logId};`;
    const deleteResult = await executeQuery(deleteQuery);

    res.send({status:"success", code:200});
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/count", async (req, res)=>{
    try {
      const authHeader = req.headers.authorization;
      let jwt;
      let rules;
      let applicationCondition;
      let time;
      const is_know = parseInt(req.query.is_know);
      if(req.query.data === "day") time = "1";
      else if(req.query.data === "week") time = "7";
      else if(req.query.data === "month") time = "30";

      if (authHeader) {
        jwt = authHeader.split(" ")[1]; // Extract the token from the "Bearer <token>" format

        if(is_know){
          const myusername = await fetch("http://192.168.8.204:8001/myusername", {
            method: "GET",
            headers: {
              Authorization: `Bearer ${jwt}`,
            },
          });
          const userData = await myusername.json();
          const user = userData.results[0];
    
          const countERRQuery = `SELECT COUNT(*) AS countERR FROM Logs.acceptedLogs_table WHERE user_id = ${user.id} AND severity="ERR"`;
          const countERRResult = await executedbLogsQuery(countERRQuery);
          const countINFOQuery = `SELECT COUNT(*) AS countINFO FROM Logs.acceptedLogs_table WHERE user_id = ${user.id} AND severity="INFO"`;
          const countINFOResult = await executedbLogsQuery(countINFOQuery);
          const countWARNINGQuery = `SELECT COUNT(*) AS countWARNING FROM Logs.acceptedLogs_table WHERE user_id = ${user.id} AND severity="WARNING"`;
          const countWARNINGResult = await executedbLogsQuery(countWARNINGQuery);
          const response = {
            total: countERRResult[0].countERR + countINFOResult[0].countINFO + countWARNINGResult[0].countWARNING,
            info: countINFOResult[0].countINFO,
            warning: countWARNINGResult[0].countWARNING,
            error: countERRResult[0].countERR
          }

          res.send(response)
              return
            }


        const roleResponse = await fetch("http://192.168.8.204:8001/role", {
          method: "GET",
          headers: {
            Authorization: `Bearer ${jwt}`,
          },
        });
        const roleData = await roleResponse.json();
        rules = roleData.results;
        applicationCondition = rules?.map((element) => `\"${element.application}\"`).toString();
        const condition = `timestamp >= DATE_SUB(NOW(), INTERVAL ${time} DAY) AND application IN (${applicationCondition})`;
  
      const countERRQuery = `SELECT COUNT(*) AS countERR FROM logsdb.table_kiber WHERE ${condition} AND severity="ERR"`;
      const countERRResult = await executeQuery(countERRQuery);
      const countINFOQuery = `SELECT COUNT(*) AS countINFO FROM logsdb.table_kiber WHERE ${condition} AND severity="INFO"`;
      const countINFOResult = await executeQuery(countINFOQuery);
      const countWARNINGQuery = `SELECT COUNT(*) AS countWARNING FROM logsdb.table_kiber WHERE ${condition} AND severity="WARNING"`;
      const countWARNINGResult = await executeQuery(countWARNINGQuery);

      const response = {
        total: countERRResult[0].countERR + countINFOResult[0].countINFO + countWARNINGResult[0].countWARNING,
        info: countINFOResult[0].countINFO,
        warning: countWARNINGResult[0].countWARNING,
        error: countERRResult[0].countERR
      }

      res.send(response)
    }
    } catch (error) {
      console.log(error);
      res.status(500).json({ error: "Internal Server Error" });
    }
      
  })

// Helper function to execute SQL queries
function executeQuery(query) {
  return new Promise((resolve, reject) => {
    db.query(query, (error, result) => {
      if (error) {
        reject(error);
      } else {
        resolve(result);
      }
    });
  });
}

function executedbLogsQuery(query) {
  return new Promise((resolve, reject) => {
    dbLogs.query(query, (error, result) => {
      if (error) {
        reject(error);
      } else {
        resolve(result);
      }
    });
  });
}


// {
//   application:"AVAST",
//   facility:"USER",
//   hostname:"192.168.0.201",
//   id:2650,
//   is_know:false,
//   message:"Avast-antivirus  192.168.5.1|192.168.0.102 INT.tm/Inspintbasl HTML:Script-inf [Susp] SHIELD_WEB https://ego-zhena.ru/templates/businessimage/img/forward.png 11-20-2023 11:38:48",
//   role:"Avast error",
//   severity:"ERR",
//   text_message:"Avast-antivirus  192.168.5.1|192.168.0.102 INT.tm/Inspintbasl HTML:Script-inf [Susp] SHIELD_WEB https://ego-zhena.ru/templates/businessimage/img/forward.png 11-20-2023 11:38:48   Avast antiwirusdan  gelen errorlar",
//   timestamp:"2023-11-20T23:38:48Z"
// }