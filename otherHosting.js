const WebSocket = require('ws')
const http = require('http')
const https = require('https')

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

    res.writeHead(400)
    res.end('Whoops your not on a websocket bogo')

})

const wss = new WebSocket.Server({ server })

const rooms = new Map()

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

wss.on('connection', (ws, req) => {

    const url = new URL(req.url, 'http://localhost')
    const roomId = url.searchParams.get('room')
    const origin = req.headers.origin

    // if (origin !== 'https://yoursite.com' && origin !== undefined) {
    //     ws.close(1008, 'Unauthorized')
    //     return
    // }

    // i know this isnt ideal and i honstly dont know if its tos or not but i dont really have any choice as cloudflare turn requires an credit card which i dont have. please if your forking use the actual turn as it can and will be shut down
    // also sorry cloudflare

    if (!roomId) {
        ws.close(1008, 'missing name')
        return
    }

    if (!rooms.has(roomId)) {

        rooms.set(roomId, new Room())
    
    }

    const room = rooms.get(roomId)
    room.handleConnection(ws, req.headers.origin, roomId)

})

server.listen(process.env.PORT || 3000, () => {
    
    console.log('Server running on port', process.env.PORT || 3000)

})