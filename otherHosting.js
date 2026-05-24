const WebSocket = require('ws')
const http = require('http')
const https = require('https')
const bcrypt = require('bcrypt')

const pingTime = 30_000
const maxMsgLength = 200;

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

    await query('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL)')
    await query('CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, message TEXT NOT NULL, roomId TEXT NOT NULL, timestamp INTEGER NOT NULL)')

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
    return result || []

}

async function saveMessage(roomId, username, message) {
    
    await query('INSERT INTO messages (roomId, username, message, timestamp) VALUES (?, ?, ?, ?)', [roomId, username, message, Date.now()]);

}

async function clearMessages(roomId) {

    await query('DELETE FROM messages WHERE roomId = ?', [roomId])

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

const wss = new WebSocket.Server({ server })
const chatWss = new WebSocket.Server({ server, path: '/chat' })

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

            const data = JSON.parse(msg)

            if (data.type === 'ping') return

            if (data.type && data.actualData) {

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

    }

    async join(ws, username, password) {
        
        const getUser = this.clients.get(username)

        if (!getUser && await loginUser(username, password) === true) {

            this.clients.set(username, ws)

        }
    
    }

    async broadcast(username, msg) {
        
        const getUser = this.clients.get(username)

        if (getUser) {

            this.clients.forEach((socket) => {
                
                if (socket.readyState === WebSocket.OPEN && socket != getUser) {

                    socket.send(JSON.stringify({type: "msg", roomId: this.roomId, actualData: msg}));
                
                }

            })

            await saveMessage(this.roomId, username, msg)
        
        }

    }

    leave(username) {

        const getUser = this.clients.get(username)

        if (getUser) {

           this.clients.delete(username)

        }
    
    }

    disconnect(ws) {

        for (const [username, socket] of this.clients) {
            
            if (socket === ws) {
                
                this.clients.delete(username)
                break
            
            }

        }

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

            if (data.roomId) {
                
                if (!chatRooms.has(data.roomId)) {

                    chatRooms.set(data.roomId, new ChatRoom(data.roomId))
        
                }

                const chatRoom = chatRooms.get(data.roomId)
                const hasJoined = chatRoom.clients.has(data.username);

                if (data.type === 'join' && data.username && data.password) {
                    
                    await chatRoom.join(ws, data.username, data.password);
                    joinedRooms.add(chatRoom);
                
                } else if (data.type === 'leave' && data.username && hasJoined) {
                    
                    chatRoom.leave(data.username)
                
                } else if (data.type === 'msg' && data.username && data.msg && data.msg.length <= maxMsgLength && hasJoined) {
                
                    await chatRoom.broadcast(data.username, `<${data.username}> ${data.msg}`);
                
                } else if (data.type === 'register' && data.username && data.password) {

                    await registerUser(data.username, data.password)

                }

            }

        } catch (err) {

            ws.close(1008, 'Invalid message')
            
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