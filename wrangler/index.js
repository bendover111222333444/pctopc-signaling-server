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
    return (result.results || []).map(row => ({

        roomId: row.roomId,
        username: row.username,
        message: row.message,
        timestamp: row.timestamp

    }))

}

async function saveMessage(env, roomId, username, message, timestamp) {

    await env.DB.prepare('INSERT INTO messages (roomId, username, message, timestamp) VALUES (?, ?, ?, ?)').bind(roomId, username, message, timestamp).run()

}

async function clearMessages(env, roomId) {

    await env.DB.prepare('DELETE FROM messages WHERE roomId = ?').bind(roomId).run()

}

const maxWssMessageLength = 100_000;
const maxMsgLength = 200;
const maxUsernameLength = 60;
const maxPasswordLength = 60;
const maxRoomIdLength = 100;

export class Room {

    constructor(state, env) {
        this.socket = new Map();
        this.socketStore = { offer: null };
        this.firstClient = true;
        this.env = env;
    }

    async fetch(request) {

        const [client, server] = Object.values(new WebSocketPair());

        const booleanCheck = this.firstClient === true;

        const origin = request.headers.get("Origin");
        const headerCheck = origin === null || origin === "file://";

        const isHost = headerCheck && booleanCheck;

        if (this.socket.has(false) && !isHost) {

            return new Response("Client already connected", { status: 403 })

        }

        if (headerCheck === true && booleanCheck === false) {

            return new Response("Host already connected in this room", { status: 403 })
        
        } else if (booleanCheck === true && headerCheck === false) {
            
            return new Response("Cannot connect to empty room as client", { status: 403 })
       
        }

        this.socket.set(isHost, server);
        server.accept();

        if (this.firstClient === true) {
            
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

            if (msg.data.length > maxWssMessageLength) return

            let data;

            try {

                data = JSON.parse(msg.data)

            } catch (err) { return }

            if (data.type === "ping") return;

            if (data.type && data.actualData && typeof data.actualData === 'object') {
                
                const target = this.socket.get(!isHost)
                
                if (isHost === true && data.type === "offer") {
                
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

            if (isHost === true) {
                
                this.firstClient = true
                this.socketStore = { offer: null }
                
                const client = this.socket.get(false)
                
                if (client) {
                
                    client.close()
                    this.socket.delete(false)
                
                }
            
            } else if (isHost === false) {
            
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
        this.messages = [];
        this.loaded = false;
        this.loading = false;
        this.env = env;
    
    }

    async ensureLoaded(roomId) {

        if (this.loaded) return
        if (this.loading) return this.loading

        this.loading = getChats(this.env, roomId).then(msgs => {

            this.messages = msgs
            this.loaded = true

        })

        return this.loading

    }

    async fetch(request) {

        const [client, server] = Object.values(new WebSocketPair());
        const url = new URL(request.url)
        const roomId = url.searchParams.get('room')
        const env = this.env
        const joinedRooms = new Set()

        server.accept();

        server.addEventListener("message", async msg => {

            try {

                const data = JSON.parse(msg.data)

                if (data.roomId && typeof data.roomId === 'string' && data.roomId.length <= maxRoomIdLength) {

                    await this.ensureLoaded(data.roomId)

                    const hasJoined = this.clients.has(data.username)

                    if (data.type === 'join' && data.username && data.password && typeof data.username === 'string' && typeof data.password === 'string' && data.username.length <= maxUsernameLength && data.password.length <= maxPasswordLength) {

                        const getUser = this.clients.get(data.username)
                        const userLoggedIn = await loginUser(env, data.username, data.password)
                        let done = false;

                        if (!getUser && userLoggedIn === true) {

                            this.clients.set(data.username, server)
                            joinedRooms.add(this)
                            server.send(JSON.stringify({type: "getMsg", msgObj: this.messages}))
                            done = true;

                        } else if (getUser) {

                            server.send(JSON.stringify({type: "error", error: "userAlreadyJoined"}));

                        } else if (userLoggedIn === false) {

                            server.send(JSON.stringify({type: "error", error: "userInvalidCredentials"}));

                        }

                        server.send(JSON.stringify({type: "conf", confType: "joined", confBoolean: done}));

                    } else if (data.type === 'leave' && data.username && typeof data.username === 'string' && data.username.length <= maxUsernameLength && hasJoined) {

                        const getUser = this.clients.get(data.username)
                        let done = false;

                        if (getUser && getUser === server) {

                            this.clients.delete(data.username)
                            done = true;

                        }

                        server.send(JSON.stringify({type: "conf", confType: "leave", confBoolean: done}));

                    } else if (data.type === 'msg' && data.username && data.msg && typeof data.username === 'string' && typeof data.msg === 'string' && data.msg.length <= maxMsgLength && data.username.length <= maxUsernameLength && hasJoined) {

                        const getUser = this.clients.get(data.username)
                        let done = false;

                        if (getUser && getUser === server) {

                            const finalMsg = `<${data.username}> ${data.msg}`
                            const timestamp = Date.now()
                            const messageObject = {roomId: data.roomId, username: data.username, message: finalMsg, timestamp: timestamp}

                            this.messages.push(messageObject);

                            await saveMessage(env, data.roomId, data.username, finalMsg, timestamp)

                            this.clients.forEach((socket) => {

                                if (socket !== server) {

                                    socket.send(JSON.stringify({type: "msg", roomId: data.roomId, msgObj: messageObject}));

                                }

                            })

                            done = true;

                        } else {

                            server.send(JSON.stringify({type: "error", error: "userNotJoined"}));

                        }

                        server.send(JSON.stringify({type: "conf", confType: "broadcast", confBoolean: done}));

                    } else if (data.type === 'register' && data.username && data.password && typeof data.username === 'string' && typeof data.password === 'string' && data.username.length <= maxUsernameLength && data.password.length <= maxPasswordLength) {

                        const registered = await registerUser(env, data.username, data.password)
                        server.send(JSON.stringify({type: "conf", confType: "registered", confBoolean: registered}));

                    } else {

                        server.send(JSON.stringify({type: "error", error: 'requestLongOrMissArg'}));

                    }

                }

            } catch (err) {

                server.close(1008, 'Invalid message')

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

        if (request.headers.get("Upgrade") !== "websocket") {

            if (new URL(request.url).pathname === "/turn-creds") {

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

        if (typeof roomId === 'string' && roomId.length > maxRoomIdLength) {
            return new Response("roomId too big", { status: 400 });
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