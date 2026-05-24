async function hashPassword(password) {

    const enc = new TextEncoder()
    const key = await crypto.subtle.importKey('raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits'])
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: enc.encode('pctopc'), iterations: 100000, hash: 'SHA-256' }, key, 256)
    
    return btoa(String.fromCharCode(...new Uint8Array(bits)))

}

async function comparePassword(password, hash) {

    return await hashPassword(password) === hash

}

async function query(env, sql, args = []) {

    const stmt = env.DB.prepare(sql)
    if (args.length > 0) return stmt.bind(...args).all()
    
    return stmt.all()

}

async function registerUser(env, username, password) {

    const exists = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first()
    
    if (exists) return false

    const hash = await hashPassword(password)

    await env.DB.prepare('INSERT INTO users (username, password) VALUES (?, ?)').bind(username, hash).run()
    return true

}

async function loginUser(env, username, password) {

    const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first()
    if (!user) return false

    return await comparePassword(password, user.password)

}

async function getChats(env, roomId) {

    const result = await env.DB.prepare('SELECT * FROM messages WHERE roomId = ? ORDER BY timestamp ASC').bind(roomId).all()
    return result.results || []

}

async function saveMessage(env, roomId, username, message) {

    await env.DB.prepare('INSERT INTO messages (roomId, username, message, timestamp) VALUES (?, ?, ?, ?)').bind(roomId, username, message, Date.now()).run()

}

async function clearMessages(env, roomId) {

    await env.DB.prepare('DELETE FROM messages WHERE roomId = ?').bind(roomId).run()

}

export class Room {

    constructor(state, env) {
        this.socket = new Map();
        this.socketStore = { offer: null };
        this.firstClient = true;
        this.env = env;
    }

    async fetch(request) {

        const [client, server] = Object.values(new WebSocketPair());

        const booleanCheck = this.firstClient == true;

        const origin = request.headers.get("Origin");
        const headerCheck = origin === null || origin === "file://";

        const isHost = headerCheck && booleanCheck;

        if (this.socket.has(false) && !isHost) {

            return new Response("Client already connected", { status: 403 })

        }

        if ((headerCheck == true && booleanCheck == false)) {

            return new Response("Host already connected in this room", { status: 403 })
        
        } else if ((booleanCheck == true && headerCheck == false)) {
            
            return new Response("Cannot connect to empty room as client", { status: 403 })
       
        }

        this.socket.set(isHost, server);
        server.accept();

        if (this.firstClient == true) {
            
            this.firstClient = false;
        
        } else {
            
            const target = this.socket.get(false);
            if (this.socketStore.offer !== null) {
            
                target.send(JSON.stringify({ type: 'offer', actualData: this.socketStore.offer }))
            
            }
            
            const host = this.socket.get(true)
            
            if (host) host.send(JSON.stringify({ type: 'clientConnected' }))
        
        }

        server.addEventListener("message", msg => {

            let hostOpp = !isHost;
            const data = JSON.parse(msg.data);

            if (data.type === "ping") return;

            if (data.type && data.actualData) {
                
                const target = this.socket.get(hostOpp)
                
                if (isHost == true && data.type == "offer") {
                
                    this.socketStore.offer = data.actualData;
                
                    const clientSocket = this.socket.get(false)
                    if (clientSocket) clientSocket.send(msg.data)
                
                } else if (target) {
                
                    target.send(msg.data);
                
                }
            
            }

        });

        server.addEventListener("close", () => {

            this.socket.delete(isHost);

            if (isHost == true) {
                
                this.firstClient = true
                this.socketStore = { offer: null }
                
                const client = this.socket.get(false)
                
                if (client) {
                
                    client.close()
                    this.socket.delete(false)
                
                }
            
            } else if (isHost == false) {
            
                this.socketStore = { offer: null }
                this.socket.delete(false)
            
                const host = this.socket.get(true)
            
                if (host) host.send(JSON.stringify({ type: 'clientDisconnected' }))
            
            }

        });

        return new Response(null, { status: 101, webSocket: client });
    
    }

}

export class ChatRoom {

    constructor(state, env) {
    
        this.clients = new Map();
        this.env = env;
    
    }

    async fetch(request) {

        const [client, server] = Object.values(new WebSocketPair());
        const url = new URL(request.url)
        const roomId = url.searchParams.get('room')
        const env = this.env

        server.accept();

        server.addEventListener("message", async msg => {

            const data = JSON.parse(msg.data)

            if (data.type === 'join') {

                const getUser = this.clients.get(data.username)

                if (!getUser && await loginUser(env, data.username, data.password) === true) {

                    this.clients.set(data.username, server)

                }

            } else if (data.type === 'leave') {

                this.clients.delete(data.username)

            } else if (data.type === 'msg') {

                const getUser = this.clients.get(data.username)

                if (getUser) {

                    this.clients.forEach((socket) => {

                        if (socket.readyState === WebSocket.OPEN) {

                            socket.send(JSON.stringify({ type: "msg", roomId: roomId, actualData: data.message }));

                        }

                    })

                    await saveMessage(env, roomId, data.username, data.message)

                }

            }

        });

        server.addEventListener("close", () => {

            for (const [username, socket] of this.clients) {

                if (socket === server) {

                    this.clients.delete(username)
                    break

                }

            }

        });

        return new Response(null, { status: 101, webSocket: client });

    }

}

export default {

    async fetch(request, env) {

        //const origin = request.headers.get("Origin")
        //if (origin !== env.ALLOWED_ORIGIN && origin !== null) {

            //return new Response("You requested to my cloudflare server no sirrie. \nIf you forked this yourself please go to /js/wrangler.toml and under vars change ALLOWED_ORGIN to a worker hosting your signaling server", { status: 403 })

        //}

        if (request.headers.get("Upgrade") !== "websocket") {

            if (new URL(request.url).pathname === "/turn-creds") {

                // i know this isnt ideal and i honstly dont know if its tos or not but i dont really have any choice as cloudflare turn requires an credit card which i dont have. please if your forking use the actual turn as it can and will be shut down
                // also sorry cloudflare

                const req = new Request("https://speed.cloudflare.com/turn-creds", {
                    headers: {
                        "Origin": "https://speed.cloudflare.com",
                        "Referer": "https://speed.cloudflare.com/"
                    }
                });

                const creds = await fetch(req);
                const data = await creds.json();

                return new Response(JSON.stringify(data), {
                    headers: {
                        "Content-Type": "application/json",
                        "Access-Control-Allow-Origin": "*"
                    }
                })

            }

            return new Response("Whoops your not on a websocket bogo", { status: 400 })

        }

        const url = new URL(request.url)
        const roomId = url.searchParams.get("room");
        const path = url.pathname;

        if (!roomId) {
            return new Response("missing name", { status: 400 });
        }

        if (path === '/chat') {

            const chatRoomClass = env.CHATROOM.idFromName(roomId);
            const stub = env.CHATROOM.get(chatRoomClass);
            return stub.fetch(request);

        } else {

            const roomClass = env.ROOM.idFromName(roomId);
            const stub = env.ROOM.get(roomClass);
            return stub.fetch(request);

        }

    }

}