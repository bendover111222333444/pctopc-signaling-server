import { Server, WebSocketServer } from 'ws';
import { DOMWindow, JSDOM } from 'jsdom';
import { randomBytes } from 'crypto';
import DOMPurify from 'dompurify';
import mongoSanitize from 'mongo-sanitize';
import http from 'http';   
import https from 'https';
import bcrypt from 'bcrypt';
import { time } from 'console';
import { json } from 'stream/consumers';
import { join } from 'path';

type DOMPurifyInstance = ReturnType<typeof DOMPurify>;

type HttpHandler = (req: http.IncomingMessage, res: http.ServerResponse) => void;
type WsHandler = (ws: WebSocket, req: http.IncomingMessage) => void;
type ErrorRes = {type : string, reason: string} | void;

type ChatMsg = { roomId: string; message: string; username: string; userId: number, timestamp: number };
type JoinMsg = { roomId: string, username: string, userId : number };

type WsMsg<TType extends string, TPayload> = { type: TType; object: TPayload | TPayload[] }; // i really had to ask claude for this one i was stuck

type JoinWsMsg = WsMsg<'JoinMsg', JoinMsg>;
type ChatWsMsg = WsMsg<'ChatMsg', ChatMsg>;
type ChatWsMsgs = WsMsg<'ChatMsgs', ChatMsg[]>;

type IncomingWsMsg = ChatWsMsg;

class Application {

    public Start() : void {



    }

    public Destroy() : void {



    }

    
    constructor() {


    }
    
}

class Utils {

    private static WebsocketTimeout = 5000; // ms

    public static GenRandString(bytesLength : number) {
        
        const randomString = randomBytes(16).toString('hex');
        return randomString
    
    }

    public static async CheckWebsocket(socket: WebSocket): Promise<boolean> {

        if (socket === undefined) return false;
        if (socket.readyState === WebSocket.CLOSING || socket.readyState === WebSocket.CLOSED) return false;

        if (socket.readyState !== WebSocket.OPEN) {

            const opened = await new Promise<boolean>((resolve) => {

                function cleanup() {

                    clearTimeout(timeOutTimer);

                    socket.removeEventListener('open', onOpen);
                    socket.removeEventListener('error', onError);

                }

                const timeOutTimer = setTimeout(() => {

                    cleanup();
                    resolve(false);

                }, this.WebsocketTimeout);

                const onOpen = () => { 

                    cleanup();
                    resolve(true);

                };
                const onError = () => { 

                    cleanup();
                    resolve(false);

                };

                socket.addEventListener('open', onOpen, { once: true });
                socket.addEventListener('error', onError, { once: true });

            });

            if (!opened) return false;
        
        }

        return true;

    }

}

class WebsocketService {

    private server: http.Server;
    private httpRoutes = new Map<string, HttpHandler>();
    private wsRoutes = new Map<string, { wss: WebSocketServer; handler: WsHandler }>();

    private fallbackHttp: HttpHandler = (_req, res) => {

        res.writeHead(404);
        res.end("Whoops you're not on a websocket bogo");

    };

    constructor() {

        this.server = http.createServer((req, res) => {

            const pathname = req.url ? new URL(req.url, 'http://localhost').pathname : undefined;

            const handler = (pathname && this.httpRoutes.get(pathname)) || this.fallbackHttp;
            handler(req, res);

        });

        this.server.on('upgrade', (req, socket, head) => {

            const pathname = new URL(req.url ?? '', 'http://localhost').pathname;
            const websocketRoute = this.wsRoutes.get(pathname);

            if (!websocketRoute) {
                socket.destroy();
                return;
            }

            websocketRoute.wss.handleUpgrade(req, socket, head, (ws : any) => {
            
                websocketRoute.handler(ws, req);
            
            });

        });

    }

    public AddHttpHandler(pathname: string, handler: HttpHandler): this {

        this.httpRoutes.set(pathname, handler);
        return this;

    }

    public AddWsHandler(pathname: string, handler: WsHandler): this {

        this.wsRoutes.set(pathname, { wss: new WebSocketServer({ noServer: true }), handler });
        return this;

    }

    public StartListen(port: number) {
    
        this.server.listen(port);
        return this;
  
    }

}

class SQLServer {

    private static SQLURL: string | undefined = process.env.SQLURL;
    private static SQLTOKEN: string | undefined = process.env.SQLTOKEN;
    private static SQLEXTRAS: string = '/v2/pipeline';
    private static QUERYMAX: number = 5;
    private static QUERYDELAY: number = 200; // ms
    private static loggedCache: Map<number, string> = new Map();
    private static usernameCache: Map<number, string> = new Map();
    private static DOMPurifyWindow: DOMWindow;
    private static DOMPurify: DOMPurifyInstance;
    private static isReady: Promise<void>;

    private static PASSMINLENGTH: number = 8;
    private static PASSMAXLENGTH: number = 256;
    private static USERMINLENGTH: number = 3;
    private static USERMAXLENGTH: number = 32;

    constructor() {

        SQLServer.DOMPurifyWindow = new JSDOM('').window;
        SQLServer.DOMPurify = DOMPurify(SQLServer.DOMPurifyWindow);

        SQLServer.isReady = (async () => {

            await SQLServer.Query('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL)', undefined)
            await SQLServer.Query('CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, userId INTEGER NOT NULL, username TEXT NOT NULL, message TEXT NOT NULL, roomId TEXT NOT NULL, timestamp INTEGER NOT NULL, FOREIGN KEY (userId) REFERENCES users(id))', undefined)
            await SQLServer.Query('CREATE INDEX IF NOT EXISTS idx_roomId ON messages (roomId)', undefined)

        })().catch((reason: any) => {

            console.error(reason);

        });

    }

    private static async Query(sql: string, args: Array<any> | undefined): Promise<any> {
    
        if (args == undefined) args = [];
        
        let res : Response | undefined = undefined;

        for (let i = 0; i < this.QUERYMAX; i++) {

            try {

                res = await fetch(`https://${this.SQLURL}${this.SQLEXTRAS}`, {
                    
                    method: 'POST',
                    headers: {
                        
                        'Authorization': `Bearer ${this.SQLTOKEN}`,
                        'Content-Type': 'application/json'

                    },

                    body: JSON.stringify({
                        
                        requests: [{ type: 'execute', stmt: { sql, args } }]
                    
                    })

                });

                if (res.ok) {

                    break;

                }

                if ((res.status >= 400 && res.status < 500) && res.status !== 429) {

                    break;

                }
                
            } catch(error) {

                console.error(`[SQL Query] Error Attempt ${i + 1} failed: `, error);
                
            }

            await new Promise<void>(resolve => setTimeout(resolve, this.QUERYDELAY));

        }
        
        if (!res) return { rows: [] };
        if (!res.ok) return { rows: [] };

        const data = await res.json();
        return data?.results?.[0]?.response?.result ?? { rows: [] };

    }

    private static ValidateUsername(username: unknown): boolean {

        if (typeof username !== 'string') {

            return false;

        }

        if (username.length < this.USERMINLENGTH || username.length > this.USERMAXLENGTH) {

            return false;

        }

        return true
        
    }

    private static ValidatePassword(password: unknown): boolean {

        if (typeof password !== 'string') {

            return false;

        }

        if (password.length < this.PASSMINLENGTH || password.length > this.PASSMAXLENGTH) {

            return false;

        }

        return true
        
    }

    public static SanitizeString(input: unknown): string {

        let clean = typeof input === 'string' ? input : String(input || '');
        clean = mongoSanitize(clean);
        clean = this.DOMPurify.sanitize(clean, { ALLOWED_TAGS: [], ALLOWED_ATTR: []});

        const lowerCheck = clean.toLowerCase().trim();
        if (lowerCheck === '__proto__' || lowerCheck === 'constructor' || lowerCheck === 'prototype') {
        
            return 'actual_cornball';
        
        }
        
        return clean.trim();

    }

    public static async GetUsernameById(userId: number): Promise<string | undefined> {

        if (this.usernameCache.has(userId)) {

            return this.usernameCache.get(userId);

        }

        const result = await this.Query('SELECT username FROM users WHERE id = ?', [userId]);
        const username = result.rows[0]?.username;

        if (username !== undefined) {

            this.usernameCache.set(userId, username);

        }

        return username;

    }

    public static async LoginUser(username: string, password: string): Promise<boolean> {
    
        const sanitizedUser = this.SanitizeString(username);

        if (this.ValidateUsername(sanitizedUser) === false) return false;
        if (this.ValidatePassword(password) === false) return false;

        const result = await(this.Query('SELECT * FROM users WHERE username = ?', [sanitizedUser]))
        const user = result.rows[0]
            
        if (!user) return false;
        if (!await bcrypt.compare(password, user.password)) return false;

        this.loggedCache.set(user.id, user.username);
        this.usernameCache.set(user.id, user.username);
        
        return true

    }

    public static async RegisterUser(username: string, password : string): Promise<boolean> {
        
        const sanitizedUser = this.SanitizeString(username);

        if (this.ValidateUsername(sanitizedUser) === false) return false;
        if (this.ValidatePassword(password) === false) return false;

        const result = await(this.Query('SELECT * FROM users WHERE username = ?', [sanitizedUser]))
        const exists = result.rows[0]

        if (exists) return false

        const hash = await bcrypt.hash(password, 10)

        await(this.Query('INSERT INTO users (username, password) VALUES (?, ?)', [sanitizedUser, hash]))

        const secResult = await(this.Query('SELECT * FROM users WHERE username = ?', [sanitizedUser]))
        const user = secResult.rows[0]

        this.loggedCache.set(user.id, randomBytes(32));
        this.usernameCache.set(user.id, user.username);

        return true

    }

    public static async GetChats(roomId : string) : Promise<Array<any>> {
    
        const sanitizedRoomId = this.SanitizeString(roomId);

        const result = await this.Query('SELECT userId, username, message, roomId, timestamp FROM messages WHERE roomId = ? ORDER BY timestamp ASC', [sanitizedRoomId]);
        return (result.rows || []).map((row : Array<any>) => ({

            roomId: row[3],
            message: row[2],
            username: row[1],
            userId: row[0],
            timestamp: row[4]
        
        }))

    }

    public static async SaveMessage(msg: ChatMsg) : Promise<void> {

        const sanitizedRoom = this.SanitizeString(msg.roomId);
        const sanitizedUser = this.SanitizeString(msg.username);
        const sanitizedMess = this.SanitizeString(msg.message);
    
        await(this.Query('INSERT INTO messages (roomId, userId, username, message, timestamp) VALUES (?, ?, ?, ?, ?)', [sanitizedRoom, msg.userId, sanitizedUser, sanitizedMess, msg.timestamp]));

    }

    public static async ClearMessages(roomId : string) : Promise<void> {

        const sanitizedRoom = this.SanitizeString(roomId);

        await(this.Query('DELETE FROM messages WHERE roomId = ?', [sanitizedRoom]))

    }

    public static IsLogged(userId: number) : boolean {

        if (this.loggedCache.get(userId)) {
        
            return true;
        
        } else {

            return false;

        }

    }

    public static async WaitUntilReady(): Promise<void> {

        return this.isReady;

    }

}

class Room {

    protected static rooms = new Map<string, Room>();

    protected clients = new Map<number, WebSocket>();
    protected roomId: string;
    protected emptyTimer: NodeJS.Timeout | null = null;
    protected static EMPTY_GRACE_MS = 30_000;

    protected constructor(roomID: string) {

        this.roomId = roomID;
        
    }

    public static Init(roomID: string): Room {

        let room = Room.rooms.get(roomID);
        if (!room) {

            room = new Room(roomID);
            Room.rooms.set(roomID, room);

        }

        return room;
    
    }

    public static Has(roomID: string): boolean {

        return Room.rooms.has(roomID);

    }

    public static List(): string[] {

        return [...Room.rooms.keys()];

    }

    public IsClient(userId: number) : boolean {

        if (this.clients.get(userId)) {
        
            return true;
        
        } else {

            return false;

        }

    }

    public AddClient(userId : number, ws: WebSocket): void {

        this.clients.set(userId, ws);

        if (this.emptyTimer) {

            clearTimeout(this.emptyTimer);
            this.emptyTimer = null;

        }

    }

    public RemoveClient(userId : number): void {

        this.clients.delete(userId);

        if (this.clients.size === 0) {
        
            this.ScheduleDestroy();
        
        }

    }

    protected ScheduleDestroy(): void {

        this.emptyTimer = setTimeout(() => {

            if (this.clients.size === 0) {

                this.Destroy();

            }

        }, Room.EMPTY_GRACE_MS);
    
    }

    protected Destroy(): void {

        Room.rooms.delete(this.roomId);

    }

}

class ChatRoom extends Room {

    constructor(roomId: string) {

        super(roomId);

    }

    override async AddClient(userId: number, ws: WebSocket): Promise<ErrorRes | void> {

        super.AddClient(userId, ws);

        const username = await SQLServer.GetUsernameById(userId);
        if (username === undefined) return {type: "LOGIN", reason: "mismatch of login tables likely not user error"};

        const chatMsgs : ChatMsg[] = (await SQLServer.GetChats(this.roomId) as ChatMsg[]);

        if (ws.readyState !== WebSocket.OPEN) { await new Promise(res => ws.addEventListener('open', res, { once: true })); }
        const sendMessage: ChatWsMsgs = {type: 'ChatMsgs', object: chatMsgs};

        const joinMsg : JoinMsg = { roomId: this.roomId, username: username, userId: userId };
        const joinedStringify = JSON.stringify(joinMsg)

        await Promise.all(

            Array.from(this.clients.entries()).map(async ([_id, ws]) => {

                const check = await Utils.CheckWebsocket(ws);
                if (check) ws.send(joinedStringify);

            })

        );

        ws.send(JSON.stringify(sendMessage));

    }

    override async RemoveClient(userId: number): Promise<ErrorRes | void> {
        


    }

    public async MessageClients(userId : number, message : string) : Promise<ErrorRes | void> {

        if (!SQLServer.IsLogged(userId)) return {type: "LOGIN", reason: "not logged in son"};

        const username = await SQLServer.GetUsernameById(userId);
        if (username === undefined) return {type: "LOGIN", reason: "mismatch of login tables likely not user error"};

        const timestamp = Math.floor(Date.now() / 1000); // in seconds
        const messageObj : ChatMsg = {roomId: this.roomId, message: message, username: username, userId: userId, timestamp: timestamp};
        SQLServer.SaveMessage(messageObj);

        const sendMessage: ChatWsMsg = {type: 'ChatMsg', object: messageObj};
        const stringifiedMsg = JSON.stringify(sendMessage)

        await Promise.all(

            Array.from(this.clients.entries()).map(async ([_id, ws]) => {

                const check = await Utils.CheckWebsocket(ws);
                if (check) ws.send(stringifiedMsg);

            })

        );

    }

}