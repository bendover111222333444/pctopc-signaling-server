const WebSocket = require('ws')
const http = require('http')
const https = require('https')
const bcrypt = require('bcrypt')

const pingTime = 30_000
const maxWssMessageLength = 100_000;
const maxMsgLength = 200;
const maxUsernameLength = 60;
const maxPasswordLength = 60;
const maxRoomIdLength = 100;

const mainChatRoom = "MainRoom"

const SQLURL = process.env.SQLURL
const SQLTOKEN = process.env.SQLTOKEN
const SERVERURL = process.env.SERVERURL

// Todo:

// add rate limitimg

async function query(sql, args = []) {

    const res = await fetch(`https://${SQLURL}/v2/pipeline`, {
        
        method: 'POST',
        headers: {
            
            'Authorization': `Bearer ${SQLTOKEN}`,
            'Content-Type': 'application/json'

        },

        body: JSON.stringify({
            
            requests: [{ type: 'execute', stmt: { sql, args } }]
        
        })

    })

    const data = await res.json()
    return data.results[0].response.result

}

(async () => {

    await query('CREATE TABLE IF NOT EXISTS user_rooms (username TEXT NOT NULL, roomId TEXT NOT NULL, PRIMARY KEY (username, roomId))')
    await query('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL)')
    await query('CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, message TEXT NOT NULL, roomId TEXT NOT NULL, timestamp INTEGER NOT NULL)')
    await query('CREATE INDEX IF NOT EXISTS idx_roomId ON messages (roomId)')

})()

async function registerUser(username, password) {
    
    const result = await(query('SELECT * FROM users WHERE username = ?', [username]))
    const exists = result.rows[0]

    if (exists) return false

    const hash = await bcrypt.hash(password, 10)

    await(query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash]))

    return true
}

async function loginUser(username, password) {
    
    const result = await query('SELECT * FROM users WHERE username = ?', [username])
    const user = result.rows[0]
        
    if (!user) return false
    return await bcrypt.compare(password, user.password)

}

async function getChats(roomId) {
    
    const result = await query('SELECT * FROM messages WHERE roomId = ? ORDER BY timestamp ASC', [roomId])
    return (result.rows || []).map(row => ({

        username: row[1],
        message: row[2],
        timestamp: row[4]
    
    }))

}

async function saveMessage(roomId, username, message, timestamp) {
    
    await query('INSERT INTO messages (roomId, username, message, timestamp) VALUES (?, ?, ?, ?)', [roomId, username, message, timestamp]);

}

async function clearMessages(roomId) {

    await query('DELETE FROM messages WHERE roomId = ?', [roomId])

}

async function addRoom(username, roomId) {

    if (this.roomId !== mainChatRoom) {

        const exists = await query('SELECT * FROM user_rooms WHERE username = ? AND roomId = ?', [username, roomId])
        if (exists.rows[0]) return false
        await query('INSERT INTO user_rooms (username, roomId) VALUES (?, ?)', [username, roomId])
        return true
    
    }

}

async function getRooms(username) {

    const result = await query('SELECT roomId FROM user_rooms WHERE username = ?', [username])
    return result.rows.map(row => row[0])

}

async function removeRoom(username, roomId) {
    
    await query('DELETE FROM user_rooms WHERE username = ? AND roomId = ?', [username, roomId])

}

const server = http.createServer(async (req, res) => {

    if (req.url === '/turn-creds') {

        const options = {

            hostname: 'speed.cloudflare.com',
            path: '/turn-creds',
            headers: {
                'Origin': 'https://speed.cloudflare.com',
                'Referer': 'https://speed.cloudflare.com/'
            }
            
        }

        https.get(options, (r) => {

            let data = ''
            r.on('data', chunk => data += chunk)
            r.on('end', () => {
                
                res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' })
                res.end(data)
            
            })
        
        })

        return

    }

    res.writeHead(200)
    res.end('Whoops your not on a websocket bogo')

})

const wss = new WebSocket.Server({ noServer: true })
const chatWss = new WebSocket.Server({ noServer: true })

server.on('upgrade', (req, socket, head) => {

    const url = new URL(req.url, 'http://localhost')

    if (url.pathname === '/chat') {

        chatWss.handleUpgrade(req, socket, head, (ws) => {

            chatWss.emit('connection', ws, req)

        })

    } else {

        wss.handleUpgrade(req, socket, head, (ws) => {

            wss.emit('connection', ws, req)

        })

    }

})

const rooms = new Map()
const chatRooms = new Map()

class Room {

    constructor() {

        this.socket = new Map()
        this.socketStore = { offer: null }
        this.firstClient = true
    
    }

    handleConnection(ws, origin, roomId) {

        const booleanCheck = this.firstClient === true
        const headerCheck = origin === null || origin === 'file://' || origin === undefined

        const isHost = headerCheck && booleanCheck

        if (this.socket.has(false) && !isHost) {

            ws.close(1008, 'Client already connected')
            return

        }

        if (headerCheck === true && booleanCheck === false) {
            
            ws.close(1008, 'Host already connected in this room')
            return

        } else if (booleanCheck === true && headerCheck === false) {
            
            ws.close(1008, 'Cannot connect to empty room as client')
            return

        }

        this.socket.set(isHost, ws)

        if (this.firstClient === true) {

            this.firstClient = false
            
        } else {
            
            const target = this.socket.get(false)

            if (this.socketStore.offer !== null) {
            
                target.send(JSON.stringify({ type: 'offer', actualData: this.socketStore.offer }))
            
            }

            const host = this.socket.get(true)
            if (host) host.send(JSON.stringify({ type: 'clientConnected' }))

        }

        ws.on('message', (msg) => {

            if (msg.length > maxWssMessageLength) return
            
            let data;

            try {
                
                data = JSON.parse(msg)
            
            } catch (err) { return }

            if (data.type && typeof data.type === 'string' && data.actualData && typeof data.actualData === 'object') {

                if (data.type === 'ping') return

                const target = this.socket.get(!isHost)

                if (isHost === true && data.type === 'offer') {
                    
                    this.socketStore.offer = data.actualData
                    
                    const clientSocket = this.socket.get(false)
                    if (clientSocket) clientSocket.send(msg.toString())
                
                } else if (target) {
                    
                    target.send(msg.toString())
                
                }
            
            }
        
        })

        ws.on('close', () => {

            this.socket.delete(isHost)

            if (isHost === true) {

                this.firstClient = true
                this.socketStore = { offer: null }
                
                const client = this.socket.get(false)
                
                if (client) {
                    client.close()
                    this.socket.delete(false)
                }

                rooms.delete(roomId)

            } else {

                this.socketStore = { offer: null }
                this.socket.delete(false)
                
                const host = this.socket.get(true)
                if (host) host.send(JSON.stringify({ type: 'clientDisconnected' }))

            }

        })

    }

}

class ChatRoom {

    constructor(roomId) {
        
        this.clients = new Map()
        this.roomId = roomId
        this.messages = [];
        this.loaded = false;
        this.loading = false;

    }

    async ensureLoaded() {
        
        if (this.loaded) return
        if (this.loading) return this.loading

        this.loading = getChats(this.roomId).then(msgs => {

            this.messages = msgs
            this.loaded = true

        })

        return this.loading

    }

    async join(ws, username, password) {
        
        const getUser = this.clients.get(username)
        const userLoggedIn = await loginUser(username, password)
        let done = false;
        
        if (ws.readyState === WebSocket.OPEN) {
            
            if (!getUser && userLoggedIn === true) {

                await addRoom(username, this.roomId);

                this.clients.set(username, ws)
                ws.send(JSON.stringify({type: "getMsg", roomId: this.roomId, msgObj: this.messages}))
                done = true;
            
            }
        
        }

        return done;
    
    }

    async broadcast(ws, username, msg) {
        
        const getUser = this.clients.get(username)
        let done = false;

        if (getUser && getUser === ws) {

            if (getUser.readyState === WebSocket.OPEN) {
                
                const timestamp = Date.now()

                const messageObject = {username: username, message: msg, timestamp: timestamp}

                this.messages.push(messageObject);
                
                await saveMessage(this.roomId, username, msg, timestamp);

                this.clients.forEach((socket) => {
                    
                    if (socket.readyState === WebSocket.OPEN && socket !== ws) {

                        socket.send(JSON.stringify({type: "msg", roomId: this.roomId, msgObj: messageObject}));
                    
                    }

                })
                
                done = true;

            }

        }

        return done;

    }

    leave(ws, username) {

        const getUser = this.clients.get(username)
        let done = false;

        if (getUser && getUser === ws) {

           this.clients.delete(username)
           done = true;

        }

        if (this.clients.size === 0) chatRooms.delete(this.roomId)
            
        return done;

    }

    disconnect(ws) {

        for (const [username, socket] of this.clients) {
            
            if (socket === ws) {
                
                this.clients.delete(username)
                break
            
            }

        }

        if (this.clients.size === 0) chatRooms.delete(this.roomId)

    }

}

const interval = setInterval(() => {
    
    wss.clients.forEach(ws => {
        
        if (ws.isAlive === false) return ws.terminate()
        ws.isAlive = false
        ws.ping()
    
    })

}, pingTime)

const chatInterval = setInterval(() => {
    
    chatWss.clients.forEach(ws => {
        
        if (ws.isAlive === false) return ws.terminate()
        ws.isAlive = false
        ws.ping()
    
    })

}, pingTime)

chatWss.on('close', () => clearInterval(interval))
wss.on('close', () => clearInterval(interval))

chatWss.on('connection', (ws, req) => {

    ws.isAlive = true
    ws.on('pong', () => ws.isAlive = true)

    const url = new URL(req.url, 'http://localhost')
    const joinedRooms = new Set()

    // if (origin !== SERVERURL && origin !== undefined) {
    //     ws.close(1008, 'Unauthorized')
    //     return
    // }

    ws.on('message', async (msg) => {

        try {

            const data = JSON.parse(msg)

            if (data.roomId && data.type && typeof data.type === 'string' && typeof data.roomId === 'string' && data.roomId.length <= maxRoomIdLength && data.type.length < maxMsgLength) {
                
                if (data.type === 'ping') return

                if (!chatRooms.has(data.roomId)) {
                        
                    chatRooms.set(data.roomId, new ChatRoom(data.roomId))
        
                }

                const chatRoom = chatRooms.get(data.roomId)
                await chatRoom.ensureLoaded();

                if (data.type === 'join' && data.username && data.password && typeof data.username === 'string' && typeof data.password === 'string' && data.username.length <= maxUsernameLength && data.password.length <= maxPasswordLength) {
                    
                    const joined = await chatRoom.join(ws, data.username, data.password);
                    ws.send(JSON.stringify({type: "conf", confType: "joined", confBoolean: joined, with: {roomId: data.roomId, username: data.username, password: data.password}}));

                    if (joined === true) {

                        joinedRooms.add(chatRoom);

                    }
                
                } else if (data.type === 'leave' && data.username && typeof data.username === 'string' && data.username.length <= maxUsernameLength) {
                    
                    const left = chatRoom.leave(ws, data.username);
                    ws.send(JSON.stringify({type: "conf", confType: "leave", confBoolean: left, with: {roomId: data.roomId, username: data.username}}));

                } else if (data.type === 'msg' && data.username && data.msg && typeof data.username === 'string' && typeof data.msg === 'string' && data.msg.length <= maxMsgLength && data.username.length <= maxUsernameLength) {
                
                   const broadcasted = await chatRoom.broadcast(ws, data.username, data.msg);
                   ws.send(JSON.stringify({type: "conf", confType: "broadcast", confBoolean: broadcasted, with: {roomId: data.roomId, username: data.username}}));
                
                } else if (data.type === 'register' && data.username && data.password && typeof data.username === 'string' && typeof data.password === 'string' && data.username.length <= maxUsernameLength && data.password.length <= maxPasswordLength) {

                    const registered = await registerUser(data.username, data.password);
                    ws.send(JSON.stringify({type: "conf", confType: "registered", confBoolean: registered, with: {roomId: data.roomId, username: data.username, password: data.password}}));
                
                } else if (data.type === 'getRooms' && data.username && data.password && typeof data.username === 'string' && typeof data.password === 'string' && data.username.length <= maxUsernameLength && data.password.length <= maxPasswordLength) {

                    const userLoggedIn = await loginUser(data.username, data.password)

                    if (userLoggedIn === true) {

                        const rooms = await getRooms(data.username);

                        for (const room of rooms) {

                            await chatRooms.get(room)?.join(ws, data.username, data.password)

                        }
                                                                        
                        ws.send(JSON.stringify({type: "getRooms"}));

                    }

                } else if (ws.readyState === WebSocket.OPEN) {

                    ws.send(JSON.stringify({type: "error", error: 'Request too long / missing arguements'}));

                }

            }

        } catch (err) {

            ws.send(JSON.stringify({type: "error", error: 'Message is invalid'}));
            
        }

    });

    ws.on('close', () => {

        joinedRooms.forEach(room => room.disconnect(ws))
    
    })

})

wss.on('connection', (ws, req) => {

    ws.isAlive = true
    ws.on('pong', () => ws.isAlive = true)

    const url = new URL(req.url, 'http://localhost')
    const roomId = url.searchParams.get('room')
    const origin = req.headers.origin

    if (roomId && typeof roomId === 'string' && roomId.length > maxRoomIdLength) {

        ws.close(1008, 'roomId too big')
        return

    }

    if (!roomId) {

        ws.close(1008, 'missing room name')
        return

    }

    // if (origin !== SERVERURL && origin !== undefined) {
    //     ws.close(1008, 'Unauthorized')
    //     return
    // }

    if (!rooms.has(roomId)) {

        rooms.set(roomId, new Room())
    
    }

    const room = rooms.get(roomId)
    room.handleConnection(ws, origin, roomId)

})

server.listen(process.env.PORT || 3000, () => {

    console.log('Server has turned tf on')

})