import { WebSocketServer } from 'ws';
import { DOMWindow, JSDOM } from 'jsdom';
import { randomBytes } from 'crypto';
import DOMPurify from 'dompurify';
import mongoSanitize from 'mongo-sanitize';
import http from 'http';
import bcrypt from 'bcrypt';

// TODO LIST:

// add session timeouts
// send chunks of messages not whole list.
// add confirmation messages
// add deleting messages
// add application class

type DOMPurifyInstance = ReturnType<typeof DOMPurify>;

type HttpHandler = (req: http.IncomingMessage, res: http.ServerResponse) => void;
type WsHandler = (ws: WebSocket, req: http.IncomingMessage) => void;
type Session = { userId: number; username: string; expiresAt: number };

type Res = { ok: boolean, returnData: any };

type RTCObject = { roomId: string; rtcType: string, rtcObj : any; username: string; userId: number; };
type ChatMsg = { roomId: string; message: string; username: string; userId: number, timestamp: number };
type JoinLeaveMsg = { roomId: string, username: string, userId : number , joining: boolean};
type ErrorPayload = { forType: string; reason: string };
type AuthPayload = { forType: string; token: string };

type WsMsg<TType extends string, TPayload> = { type: TType; object: TPayload | TPayload[] }; // i really had to ask claude for this one i was stuck

type IncomingMsg = { type: string; [key: string]: unknown };

type JoinLeaveWsMsg = WsMsg<'JoinLeaveMsg', JoinLeaveMsg>;
type RTCObjectWs = WsMsg<'RTCObject', RTCObject>;
type ChatWsMsg = WsMsg<'ChatMsg', ChatMsg>;
type ChatWsMsgs = WsMsg<'ChatMsgs', ChatMsg[]>;
type ErrorWsMsg = WsMsg<'Error', ErrorPayload>;
type AuthWsMsg = WsMsg<'Auth', AuthPayload>;

type WsConnectionState = { sessionId: string | null; joinedChatRooms: Set<string>; joinedRtcRooms: Set<string>; };

class Application {

    private wsService: WebsocketService;
    private sqlServer: SQLServer;
    private connectionState = new WeakMap<WebSocket, WsConnectionState>();
    private heartbeatIntervals: NodeJS.Timeout[] = [];

    private static PING_INTERVAL_MS = 30_000;

    constructor() {

        this.wsService = new WebsocketService();
        this.sqlServer = new SQLServer();

    }

    public async Start(): Promise<void> {

        await SQLServer.WaitUntilReady();

        this.wsService
            .AddWsHandler('/chat', (ws, req) => this.HandleChatConnection(ws))
            .AddWsHandler('/rtc', (ws, req) => this.HandleRtcConnection(ws))
            .StartListen(Number(process.env.PORT) || 3000);

        console.log("listening on port 3000")

    }

    public Destroy(): void {

        this.heartbeatIntervals.forEach((interval) => clearInterval(interval));
        this.heartbeatIntervals = [];

    }

    // shared helpers

    private StartHeartbeat(sockets: Set<WebSocket>): void {

        const interval = setInterval(() => {

            sockets.forEach((ws: any) => {

                if (ws.isAlive === false) {

                    ws.terminate();
                    sockets.delete(ws);
                    return;

                }

                ws.isAlive = false;
                ws.ping();

            });

        }, Application.PING_INTERVAL_MS);

        this.heartbeatIntervals.push(interval);

    }

    // chat route

    private chatSockets = new Set<WebSocket>();

    private HandleChatConnection(ws: WebSocket): void {

        (ws as any).isAlive = true;
        ws.addEventListener('pong', () => { (ws as any).isAlive = true; });

        this.chatSockets.add(ws);
        if (this.chatSockets.size === 1) this.StartHeartbeat(this.chatSockets);

        this.connectionState.set(ws, { sessionId: null, joinedChatRooms: new Set(), joinedRtcRooms: new Set() });

        ws.addEventListener('message', async (event: any) => {

            await this.DispatchChat(ws, event.data.toString());

        });

        ws.addEventListener('close', async () => {

            this.chatSockets.delete(ws);
            await this.CleanupChatConnection(ws);

        });

    }

    private async DispatchChat(ws: WebSocket, rawString: string): Promise<void> {

        const rateCheck = WebsocketService.RateLimitCheck(ws);
        if (Utils.IsErr(rateCheck)) { await Messages.ErrorMsg('rateLimit', rateCheck.returnData, ws, false); return; }

        const parsed = IncomingValidator.ParseIncoming(rawString);
        if (Utils.IsErr(parsed)) { await Messages.ErrorMsg('parse', parsed.returnData, ws, false); return; }

        const msg = parsed.returnData as IncomingMsg;
        const state = this.connectionState.get(ws);
        if (!state) return;

        switch (msg.type) {

            case 'login': {

                const validated = IncomingValidator.ValidateAuth(msg);
                if (Utils.IsErr(validated)) { await Messages.ErrorMsg('login', validated.returnData, ws, false); return; }

                const { username, password } = validated.returnData;

                if (IncomingValidator.ValidateUsernameSize(username) === false) { await Messages.ErrorMsg('login', 'bad username or password', ws, false); return; }
                if (IncomingValidator.ValidatePasswordSize(password) === false) { await Messages.ErrorMsg('login', 'bad username or password', ws, false); return; }

                const loginResult = await SQLServer.LoginUser(username, password);

                if (Utils.IsErr(loginResult)) { await Messages.ErrorMsg('login', loginResult.returnData, ws, false); return; }

                state.sessionId = loginResult.returnData;
                await Messages.AuthMsg('login', loginResult.returnData, ws, false);

                return;

            }

            case 'register': {

                const validated = IncomingValidator.ValidateAuth(msg);
                if (Utils.IsErr(validated)) { await Messages.ErrorMsg('register', validated.returnData, ws, false); return; }

                const { username, password } = validated.returnData;

                if (IncomingValidator.ValidateUsernameSize(username) === false) { await Messages.ErrorMsg('register', 'bad username', ws, false); return; }
                if (IncomingValidator.ValidatePasswordSize(password) === false) { await Messages.ErrorMsg('register', 'bad password', ws, false); return; }

                const registerResult = await SQLServer.RegisterUser(username, password);

                if (Utils.IsErr(registerResult)) { await Messages.ErrorMsg('register', registerResult.returnData, ws, false); return; }

                state.sessionId = registerResult.returnData;
                await Messages.AuthMsg('register', registerResult.returnData, ws, false);

                return;

            }

            case 'joinChat': {

                const validated = IncomingValidator.ValidateJoinChat(msg);
                if (Utils.IsErr(validated)) { await Messages.ErrorMsg('joinChat', validated.returnData, ws, false); return; }

                const { sessionId, roomId } = validated.returnData;
                if (!IncomingValidator.ValidateRoomId(roomId)) { await Messages.ErrorMsg('joinChat', 'bad roomId', ws, false); return; }

                const session = await SessionStore.Validate(sessionId);
                if (Utils.IsErr(session)) { await Messages.ErrorMsg('joinChat', session.returnData, ws, false); return; }

                const roomResult = await ChatRoom.Init(roomId);
                if (Utils.IsErr(roomResult)) { await Messages.ErrorMsg('joinChat', roomResult.returnData, ws, false); return; }

                const room = roomResult.returnData as ChatRoom;
                const joinResult = await room.JoinChat(sessionId, session.returnData, ws);

                if (Utils.IsErr(joinResult)) { await Messages.ErrorMsg('joinChat', joinResult.returnData, ws, false); return; }

                state.joinedChatRooms.add(roomId);

                return;

            }

            case 'leaveChat': {

                const validated = IncomingValidator.ValidateLeaveChat(msg);
                if (Utils.IsErr(validated)) { await Messages.ErrorMsg('leaveChat', validated.returnData, ws, false); return; }

                const { sessionId, roomId } = validated.returnData;

                const session = await SessionStore.Validate(sessionId);
                if (Utils.IsErr(session)) { await Messages.ErrorMsg('leaveChat', session.returnData, ws, false); return; }

                const roomResult = await ChatRoom.Init(roomId);
                if (Utils.IsErr(roomResult)) { await Messages.ErrorMsg('leaveChat', roomResult.returnData, ws, false); return; }

                const room = roomResult.returnData as ChatRoom;
                const leaveResult = await room.LeaveChat(sessionId, session.returnData);

                if (Utils.IsErr(leaveResult)) { await Messages.ErrorMsg('leaveChat', leaveResult.returnData, ws, false); return; }

                state.joinedChatRooms.delete(roomId);

                return;

            }

            case 'messageChat': {

                const validated = IncomingValidator.ValidateMessageChat(msg);
                if (Utils.IsErr(validated)) { await Messages.ErrorMsg('messageChat', validated.returnData, ws, false); return; }

                const { sessionId, roomId, message } = validated.returnData;
                if (IncomingValidator.ValidateMessageSize(message) === false) { await Messages.ErrorMsg('messageChat', 'message bad size', ws, false); return; }

                const session = await SessionStore.Validate(sessionId);
                if (Utils.IsErr(session)) { await Messages.ErrorMsg('messageChat', session.returnData, ws, false); return; }

                const roomResult = await ChatRoom.Init(roomId);
                if (Utils.IsErr(roomResult)) { await Messages.ErrorMsg('messageChat', roomResult.returnData, ws, false); return; }

                const room = roomResult.returnData as ChatRoom;
                const messageResult = await room.MessageChat(sessionId, session.returnData, message);

                if (Utils.IsErr(messageResult)) { await Messages.ErrorMsg('messageChat', messageResult.returnData, ws, false); return; }

                return;

            }

            default:

                await Messages.ErrorMsg('dispatch', `unknown type "${msg.type}"`, ws, false);
                return;

        }

    }

    // rtc route

    private rtcSockets = new Set<WebSocket>();

    private HandleRtcConnection(ws: WebSocket): void {

        (ws as any).isAlive = true;
        ws.addEventListener('pong', () => { (ws as any).isAlive = true; });

        this.rtcSockets.add(ws);
        if (this.rtcSockets.size === 1) this.StartHeartbeat(this.rtcSockets);

        this.connectionState.set(ws, { sessionId: null, joinedChatRooms: new Set(), joinedRtcRooms: new Set() });

        ws.addEventListener('message', async (event: any) => {

            await this.DispatchRtc(ws, event.data.toString());

        });

        ws.addEventListener('close', async () => {

            this.rtcSockets.delete(ws);
            await this.CleanupRtcConnection(ws);

        });

    }

    private async DispatchRtc(ws: WebSocket, rawString: string): Promise<void> {

        const rateCheck = WebsocketService.RateLimitCheck(ws);
        if (Utils.IsErr(rateCheck)) { await Messages.ErrorMsg('rateLimit', rateCheck.returnData, ws, false); return; }

        const parsed = IncomingValidator.ParseIncoming(rawString);
        if (Utils.IsErr(parsed)) { await Messages.ErrorMsg('parse', parsed.returnData, ws, false); return; }

        const msg = parsed.returnData as IncomingMsg;
        const state = this.connectionState.get(ws);
        if (!state) return;

        switch (msg.type) {

            case 'joinRTC': {

                const validated = IncomingValidator.ValidateJoinRTC(msg);
                if (Utils.IsErr(validated)) { await Messages.ErrorMsg('joinRTC', validated.returnData, ws, false); return; }

                const { sessionId, roomId, wantsHost } = validated.returnData;
                if (!IncomingValidator.ValidateRoomId(roomId)) { await Messages.ErrorMsg('joinRTC', 'bad roomId', ws, false); return; }

                const session = await SessionStore.Validate(sessionId);
                if (Utils.IsErr(session)) { await Messages.ErrorMsg('joinRTC', session.returnData, ws, false); return; }

                const roomResult = await SignalingRoom.Init(roomId);
                if (Utils.IsErr(roomResult)) { await Messages.ErrorMsg('joinRTC', roomResult.returnData, ws, false); return; }

                const room = roomResult.returnData as SignalingRoom;
                const joinResult = await room.JoinRTC(sessionId, session.returnData, ws, wantsHost);

                if (Utils.IsErr(joinResult)) { await Messages.ErrorMsg('joinRTC', joinResult.returnData, ws, false); return; }

                state.joinedRtcRooms.add(roomId);

                return;

            }

            case 'leaveRTC': {

                const validated = IncomingValidator.ValidateLeaveRTC(msg);
                if (Utils.IsErr(validated)) { await Messages.ErrorMsg('leaveRTC', validated.returnData, ws, false); return; }

                const { sessionId, roomId } = validated.returnData;

                const session = await SessionStore.Validate(sessionId);
                if (Utils.IsErr(session)) { await Messages.ErrorMsg('leaveRTC', session.returnData, ws, false); return; }

                const roomResult = await SignalingRoom.Init(roomId);
                if (Utils.IsErr(roomResult)) { await Messages.ErrorMsg('leaveRTC', roomResult.returnData, ws, false); return; }

                const room = roomResult.returnData as SignalingRoom;
                const leaveResult = await room.LeaveRTC(sessionId, session.returnData);

                if (Utils.IsErr(leaveResult)) { await Messages.ErrorMsg('leaveRTC', leaveResult.returnData, ws, false); return; }

                state.joinedRtcRooms.delete(roomId);

                return;

            }

            case 'messageRTC': {

                const validated = IncomingValidator.ValidateMessageRTC(msg);
                if (Utils.IsErr(validated)) { await Messages.ErrorMsg('messageRTC', validated.returnData, ws, false); return; }

                const { sessionId, roomId, rtcType, rtcObj } = validated.returnData;

                const session = await SessionStore.Validate(sessionId);
                if (Utils.IsErr(session)) { await Messages.ErrorMsg('messageRTC', session.returnData, ws, false); return; }

                const roomResult = await SignalingRoom.Init(roomId);
                if (Utils.IsErr(roomResult)) { await Messages.ErrorMsg('messageRTC', roomResult.returnData, ws, false); return; }

                const room = roomResult.returnData as SignalingRoom;
                const messageResult = await room.MessageRTC(sessionId, session.returnData, rtcType, rtcObj);

                if (Utils.IsErr(messageResult)) { await Messages.ErrorMsg('messageRTC', messageResult.returnData, ws, false); return; }

                return;

            }

            default:

                await Messages.ErrorMsg('dispatch', `unknown type "${msg.type}"`, ws, false);
                return;

        }

    }

    // shared cleanup

    private async CleanupChatConnection(ws: WebSocket): Promise<void> {

        const state = this.connectionState.get(ws);
        if (!state || !state.sessionId) return;

        const session = await SessionStore.Validate(state.sessionId);
        if (Utils.IsErr(session)) return;

        for (const roomId of state.joinedChatRooms) {

            const roomResult = await ChatRoom.Init(roomId);
            if (!Utils.IsErr(roomResult)) {

                await (roomResult.returnData as ChatRoom).LeaveChat(state.sessionId, session.returnData);

            }

        }

    }

    private async CleanupRtcConnection(ws: WebSocket): Promise<void> {

        const state = this.connectionState.get(ws);
        if (!state || !state.sessionId) return;

        const session = await SessionStore.Validate(state.sessionId);
        if (Utils.IsErr(session)) return;

        for (const roomId of state.joinedRtcRooms) {

            const roomResult = await SignalingRoom.Init(roomId);
            if (!Utils.IsErr(roomResult)) {

                await (roomResult.returnData as SignalingRoom).LeaveRTC(state.sessionId, session.returnData);

            }

        }

    }

}

class Config {

    public static readonly PASS_MIN_LENGTH: number = 8;
    public static readonly PASS_MAX_LENGTH: number = 256;
    public static readonly USER_MIN_LENGTH: number = 3;
    public static readonly USER_MAX_LENGTH: number = 32;
    public static readonly MESS_MIN_LENGTH: number = 1;
    public static readonly MESS_MAX_LENGTH: number = 500;

    public static readonly DEBUG_MODE : boolean = true;

    public static readonly MAX_ROOM_SIZE : number = 2;
    public static readonly MAX_HOSTS : number = 1;
    public static readonly MAX_CLIENTS : number = 1;

    public static readonly SESSION_TOKEN_BYTES = 32;
    public static readonly SESSION_TTL_MS = 24 * 60 * 60 * 1000;

    public static readonly WS_RATE_LIMIT = 5; // every second
    public static readonly WS_RATE_WINDOW_MS = 1000;
    public static readonly WS_TIMEOUT_MS = 5000; // ms
    
    public static readonly ROOM_ID_MAX_LENGTH: number = 100;

    public static readonly RTC_SIZE_MIN = 1;
    public static readonly RTC_SIZE_CONSTRAINTS: Record<string, number> = {
        'offer': 64 * 1024,
        'answer': 64 * 1024,
        'ice-candidate': 2 * 1024,
        'configuration': 4 * 1024,
    };

    public static readonly QUERYMAX: number = 5;
    public static readonly QUERYDELAY: number = 200; // ms

}

class Utils {

    private static appendError = `(RES) `

    public static GenRandString(bytesLength : number) : string {
        
        const randomString = randomBytes(bytesLength).toString('hex');
        return randomString
    
    }

    public static IsErr(res: Res): boolean {

        return res.ok === true;

    }

    public static Ok(returnData?: any): Res {

        return { ok: true, returnData };

    }

    public static Err(reason: string): Res {

        const returnObject = { ok: false, returnData: reason };

        if (Config.DEBUG_MODE === false) return returnObject;

        if (!reason) {

            console.warn(`${this.appendError}ERROR: Missing error reason`);

        }

        console.error(`${this.appendError}${reason}`);

        return returnObject;

    }

    public static IsValidRTCObject(obj: unknown, rtcType: string): Res {

        const sizeLimit = Config.RTC_SIZE_CONSTRAINTS[rtcType];
        if (sizeLimit === undefined) return Utils.Err(`RTC ERR: unknown rtcType "${rtcType}"`);

        const serialized = JSON.stringify(obj);
        const byteLength = Buffer.byteLength(serialized, 'utf8');

        if (byteLength < Config.RTC_SIZE_MIN) return Utils.Err(`RTC ERR: ${rtcType} payload too small`);
        if (byteLength > sizeLimit) return Utils.Err(`RTC ERR: ${rtcType} payload exceeds max ${sizeLimit} bytes`);

        if (typeof obj !== 'object' || obj === null) return Utils.Err(`RTC ERR: ${rtcType} payload not an object`);

        const candidate = obj as Record<string, unknown>;

        if (rtcType === 'offer' || rtcType === 'answer') {

            if (typeof candidate.type !== 'string' || typeof candidate.sdp !== 'string') {

                return Utils.Err(`RTC ERR: ${rtcType} missing type/sdp`);

            }

            return Utils.Ok(obj);

        }

        if (rtcType === 'ice-candidate') {

            if (typeof candidate.candidate !== 'string') {

                return Utils.Err(`RTC ERR: ice-candidate missing candidate`);

            }

            return Utils.Ok(obj);

        }

        if (rtcType === 'configuration') {

            if (!Array.isArray(candidate.iceServers)) {

                return Utils.Err(`RTC ERR: configuration missing iceServers`);

            }

            return Utils.Ok(obj);

        }

        return Utils.Err(`RTC ERR: unhandled rtcType "${rtcType}"`);

    }

}

class IncomingValidator {

    public static ParseIncoming(raw: string): Res {

        let parsed: unknown;

        try {

            parsed = JSON.parse(raw);

        } catch {

            return Utils.Err("PARSE ERR: invalid JSON");

        }

        if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {

            return Utils.Err("PARSE ERR: payload must be a JSON object");

        }

        const obj = parsed as Record<string, unknown>;

        if (typeof obj.type !== 'string') {

            return Utils.Err("PARSE ERR: missing or invalid 'type' field");

        }

        return Utils.Ok(obj as IncomingMsg);

    }

    public static ValidateJoinChat(msg: Record<string, unknown>): Res {

        if (typeof msg.sessionId !== 'string') return Utils.Err("VALIDATE ERR: join missing sessionId");
        if (typeof msg.roomId !== 'string') return Utils.Err("VALIDATE ERR: join missing roomId");

        return Utils.Ok({ sessionId: msg.sessionId, roomId: msg.roomId });

    }

    public static ValidateMessageChat(msg: Record<string, unknown>): Res {

        if (typeof msg.sessionId !== 'string') return Utils.Err("VALIDATE ERR: msg missing sessionId");
        if (typeof msg.roomId !== 'string') return Utils.Err("VALIDATE ERR: msg missing roomId");
        if (typeof msg.message !== 'string') return Utils.Err("VALIDATE ERR: msg missing message text");

        return Utils.Ok({ sessionId: msg.sessionId, roomId: msg.roomId, message: msg.message });

    }

    public static ValidateJoinRTC(msg: Record<string, unknown>): Res {

        if (typeof msg.sessionId !== 'string') return Utils.Err("VALIDATE ERR: rtc join missing sessionId");
        if (typeof msg.roomId !== 'string') return Utils.Err("VALIDATE ERR: rtc join missing roomId");
        if (typeof msg.wantsHost !== 'boolean') return Utils.Err("VALIDATE ERR: rtc join missing wantsHost");

        return Utils.Ok({ sessionId: msg.sessionId, roomId: msg.roomId, wantsHost: msg.wantsHost });

    }

    public static ValidateMessageRTC(msg: Record<string, unknown>): Res {

        if (typeof msg.sessionId !== 'string') return Utils.Err("VALIDATE ERR: rtc msg missing sessionId");
        if (typeof msg.roomId !== 'string') return Utils.Err("VALIDATE ERR: rtc msg missing roomId");
        if (typeof msg.rtcType !== 'string') return Utils.Err("VALIDATE ERR: rtc msg missing rtcType");

        const objCheck = Utils.IsValidRTCObject(msg.rtcObj, msg.rtcType);
        if (Utils.IsErr(objCheck)) return objCheck;

        return Utils.Ok({ sessionId: msg.sessionId, roomId: msg.roomId, rtcType: msg.rtcType, rtcObj: objCheck.returnData });

    }

    public static ValidateRoomId(roomId: unknown): boolean {

        return typeof roomId === 'string' && roomId.length > 0 && roomId.length <= Config.ROOM_ID_MAX_LENGTH;

    }

    public static ValidateAuth(msg: Record<string, unknown>): Res {

        if (typeof msg.username !== 'string') return Utils.Err("VALIDATE ERR: auth missing username");
        if (typeof msg.password !== 'string') return Utils.Err("VALIDATE ERR: auth missing password");

        return Utils.Ok({ username: msg.username, password: msg.password });

    }

    public static ValidateLeaveChat(msg: Record<string, unknown>): Res {

        if (typeof msg.sessionId !== 'string') return Utils.Err("VALIDATE ERR: leave missing sessionId");
        if (typeof msg.roomId !== 'string') return Utils.Err("VALIDATE ERR: leave missing roomId");

        return Utils.Ok({ sessionId: msg.sessionId, roomId: msg.roomId });

    }

    public static ValidateLeaveRTC(msg: Record<string, unknown>): Res {

        if (typeof msg.sessionId !== 'string') return Utils.Err("VALIDATE ERR: rtc leave missing sessionId");
        if (typeof msg.roomId !== 'string') return Utils.Err("VALIDATE ERR: rtc leave missing roomId");

        return Utils.Ok({ sessionId: msg.sessionId, roomId: msg.roomId });

    }
    
    public static ValidateUsernameSize(username: string): boolean {

        if (username.length < Config.USER_MIN_LENGTH || username.length > Config.USER_MAX_LENGTH) {

            return false;

        }

        return true
        
    }

    public static ValidatePasswordSize(password: string): boolean {

        if (password.length < Config.PASS_MIN_LENGTH || password.length > Config.PASS_MAX_LENGTH) {

            return false;

        }

        return true
        
    }

    public static ValidateMessageSize(message: string): boolean {

        if (message.length < Config.MESS_MIN_LENGTH || message.length > Config.MESS_MAX_LENGTH) {

            return false;

        }

        return true
        
    }

}

class WebsocketService {

    private static rateLimitMap = new WeakMap<WebSocket, number[]>();

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

    public static async CheckWebsocket(socket: WebSocket): Promise<Res> {

        if (socket === undefined) return Utils.Err("WS ERROR: check websocket socked undefined");
        if (socket.readyState === WebSocket.CLOSING || socket.readyState === WebSocket.CLOSED) return Utils.Err("WS ERROR: check websocket socket closing");

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

                }, Config.WS_TIMEOUT_MS);

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

            if (!opened) return Utils.Err("WS ERROR: socket not opened but opened");
        
        }

        return Utils.Ok();

    }

    public static async SendWebsockets(sockets : WebSocket[] | WebSocket, stringifiedMsg : string) : Promise<Res> {

        if (Array.isArray(sockets)) {

            await Promise.all(

                Array.from(sockets).map(async (ws) => {

                    const check = await this.CheckWebsocket(ws);
                    if (!Utils.IsErr(check)) ws.send(stringifiedMsg);

                })

            );

        } else {

            const check = await this.CheckWebsocket(sockets);
            if (!Utils.IsErr(check)) sockets.send(stringifiedMsg);

        }
        
        return Utils.Ok();

    }

    public static RateLimitCheck(ws: WebSocket): Res {

        const timeNow = Date.now();
        const timestamps = this.rateLimitMap.get(ws) ?? [];

        const recent = timestamps.filter((time) => timeNow - time < Config.WS_RATE_WINDOW_MS);

        if (recent.length >= Config.WS_RATE_LIMIT) {

            this.rateLimitMap.set(ws, recent);
            return Utils.Err("WS ERROR: Rate limit reached");

        }

        recent.push(timeNow);
        this.rateLimitMap.set(ws, recent);

        return Utils.Ok();

    }


    public AddHttpHandler(pathname: string, handler: HttpHandler): this {

        this.httpRoutes.set(pathname, handler);
        return this;

    }

    public AddWsHandler(pathname: string, handler: WsHandler): this {

        this.wsRoutes.set(pathname, { wss: new WebSocketServer({ noServer: true }), handler });
        return this;

    }

    public StartListen(port: number) : this {
    
        this.server.listen(port);
        return this;
  
    }

}

class Messages {

    // async isnt nessasary but is there for consistancy
    public static async JoinLeaveMsg(roomId : string, websockets : WebSocket[], username : string, userId: number, joining : boolean, returnMessage : boolean) : Promise<Res> {

        const joinLeaveMsg : JoinLeaveMsg = { roomId: roomId, username: username, userId: userId , joining: joining};
        const joinLeaveWsMsg: JoinLeaveWsMsg = { type: 'JoinLeaveMsg', object: joinLeaveMsg};

        await WebsocketService.SendWebsockets(websockets, JSON.stringify(joinLeaveWsMsg));

        if (returnMessage === true) {

            return Utils.Ok(joinLeaveMsg)

        }

        return Utils.Ok()

    }

    // same here async is not nessasary
    public static async RTCMsg(roomId: string, websockets : WebSocket[], rtcType : string, rtcObj : any, username: string, userId: number, returnMessage : boolean) : Promise<Res> {

        const rtcMsg : RTCObject = { roomId: roomId, rtcType : rtcType, rtcObj : rtcObj, username : username, userId : userId}
        const rtcWsMsg: RTCObjectWs = { type: 'RTCObject', object: rtcMsg};

        await WebsocketService.SendWebsockets(websockets, JSON.stringify(rtcWsMsg))

        if (returnMessage === true) {

            return Utils.Ok(rtcMsg)

        }

        return Utils.Ok()

    }

    // same here async is not nessasary
    public static async AuthMsg(forType: string, token: string, ws: WebSocket, returnMessage : boolean) : Promise<Res> {

        const authPayload : AuthPayload = { forType: forType, token: token };
        const authWsMsg: AuthWsMsg = { type: 'Auth', object: authPayload };

        await WebsocketService.SendWebsockets(ws, JSON.stringify(authWsMsg));

        if (returnMessage === true) {

            return Utils.Ok(authPayload)

        }

        return Utils.Ok()

    }

    public static async GiveMessagesMsg(roomId: string, messages : ChatMsg[], websocket : WebSocket, returnMessage : boolean) : Promise<Res> {

        const chatsMessage: ChatWsMsgs = {type: 'ChatMsgs', object: messages};

        await WebsocketService.SendWebsockets(websocket, JSON.stringify(chatsMessage))

        if (returnMessage === true) {

            return Utils.Ok(messages)

        }

        return Utils.Ok()

    }

    public static async MessageMsg(roomID: string, websockets : WebSocket[], message : string, username : string, userId : number, returnMessage : boolean) : Promise<Res> {

        const timestamp = Math.floor(Date.now() / 1000); // in seconds
        const messageObj : ChatMsg = {roomId: roomID, message: message, username: username, userId: userId, timestamp: timestamp};
        const saveMess = await SQLServer.SaveMessage(messageObj);
        if (Utils.IsErr(saveMess)) return saveMess;

        const sendMessage: ChatWsMsg = {type: 'ChatMsg', object: messageObj};

        await WebsocketService.SendWebsockets(websockets, JSON.stringify(sendMessage));

        if (returnMessage === true) {

            return Utils.Ok(messageObj)

        }

        return Utils.Ok()
    
    }

    public static async ErrorMsg(forType: string, reason: string, ws: WebSocket, returnMessage : boolean) : Promise<Res> {

        const errorPayload : ErrorPayload = { forType: forType, reason: reason };
        const errorWsMsg: ErrorWsMsg = { type: 'Error', object: errorPayload };

        await WebsocketService.SendWebsockets(ws, JSON.stringify(errorWsMsg));

        if (returnMessage === true) {

            return Utils.Ok(errorPayload)

        }

        return Utils.Ok()

    }

}

class SessionStore {

    private static sessions = new Map<string, Session>();
    private static userTokens = new Map<number, string>();

    public static Create(userId: number, username: string): Res {

        const existingToken = this.userTokens.get(userId);
        if (existingToken) {

            this.sessions.delete(existingToken);

        }

        const token = Utils.GenRandString(Config.SESSION_TOKEN_BYTES);
        this.sessions.set(token, { userId, username, expiresAt: Date.now() + Config.SESSION_TTL_MS });
        this.userTokens.set(userId, token);

        return Utils.Ok(token);

    }

    public static Validate(token: string | undefined): Res {

        if (!token) return Utils.Err("SESSION: no token provided");

        const session = this.sessions.get(token);
        if (!session) return Utils.Err("SESSION: invalid token");

        if (Date.now() > session.expiresAt) {

            this.sessions.delete(token);
            this.userTokens.delete(session.userId);
            return Utils.Err("SESSION: expired");

        }

        return Utils.Ok(session);

    }

    public static Revoke(token: string): Res {

        const session = this.sessions.get(token);
        const existed = this.sessions.delete(token);

        if (session) this.userTokens.delete(session.userId);

        return existed ? Utils.Ok(undefined) : Utils.Err("SESSION: token not found");

    }

}

class SQLServer {

    private static SQLURL: string | undefined = process.env.SQLURL;
    private static SQLTOKEN: string | undefined = process.env.SQLTOKEN;
    private static SQLEXTRAS: string = '/v2/pipeline';

    private static HASH_COUNT = 12; // match with dummy hash
    private static DUMMY_HASH = "$2a$12$uhm85cq9eC4wfsgAnOwnZOzj9frmq8c1Q/2RgdwHn3vDyVDHtJi4K";

    private static DOMPurifyWindow: DOMWindow;
    private static DOMPurify: DOMPurifyInstance;
    private static isReady: Promise<void>;

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

    private static async Query(sql: string, args: Array<any> | undefined): Promise<Res> {
    
        if (args == undefined) args = [];
        
        let res : Response | undefined = undefined;

        for (let i = 0; i < Config.QUERYMAX; i++) {

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

                console.warn(`SQL Query: Error Attempt ${i + 1} failed: `, error);
                
            }

            await new Promise<void>(resolve => setTimeout(resolve, Config.QUERYDELAY));

        }
        
        if (!res) return Utils.Err("SQL ERROR: no response after retries");
        if (!res.ok) return Utils.Err(`SQL ERROR: request failed with status ${res.status}`);

        const data = await res.json();
        const result = data?.results?.[0]?.response?.result;

        if (!result) return Utils.Err("SQL ERROR: malformed response shape");

        return Utils.Ok(result);

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

    public static async LoginUser(username: string, password: string): Promise<Res> {

        const sanitizedUser = this.SanitizeString(username);

        if (IncomingValidator.ValidateUsernameSize(sanitizedUser) === false) return Utils.Err("LOGIN: bad username or password");
        if (IncomingValidator.ValidatePasswordSize(password) === false) return Utils.Err("LOGIN: bad username or password");

        const result = await this.Query('SELECT * FROM users WHERE username = ?', [sanitizedUser]);
        if (Utils.IsErr(result)) return result;
        const user = result.returnData.rows[0];

        const passwordMatches = await bcrypt.compare(password, user ? user.password : this.DUMMY_HASH);

        if (!user || !passwordMatches) return Utils.Err("LOGIN: bad username or password");

        const session = SessionStore.Create(user.id, user.username);

        return Utils.Ok(session.returnData);

    }

    public static async RegisterUser(username: string, password : string): Promise<Res> {
        
        const sanitizedUser = this.SanitizeString(username);

        if (IncomingValidator.ValidateUsernameSize(sanitizedUser) === false) return Utils.Err("LOGIN: bad username or password");
        if (IncomingValidator.ValidatePasswordSize(password) === false) return Utils.Err("LOGIN: bad username or password");

        const result = await(this.Query('SELECT * FROM users WHERE username = ?', [sanitizedUser]))
        if (Utils.IsErr(result)) return result;
        const exists = result.returnData.rows[0];

        if (exists) return Utils.Err("REGISTER: username taken");

        const hash = await bcrypt.hash(password, this.HASH_COUNT)

        const insertResult = await(this.Query('INSERT INTO users (username, password) VALUES (?, ?)', [sanitizedUser, hash]));
        if (Utils.IsErr(insertResult)) return Utils.Err("REGISTER: username taken");

        const secResult = await(this.Query('SELECT * FROM users WHERE username = ?', [sanitizedUser]))
        if (Utils.IsErr(secResult)) return secResult;
        const user = secResult.returnData.rows[0];

        if (!user) return Utils.Err("REGISTER: registration failed, try again");

        const session = SessionStore.Create(user.id, user.username);

        return Utils.Ok(session.returnData);

    }

    public static async GetChats(roomId : string) : Promise<Res> {
    
        const sanitizedRoomId = this.SanitizeString(roomId);

        const result = await this.Query('SELECT userId, username, message, roomId, timestamp FROM messages WHERE roomId = ? ORDER BY timestamp ASC', [sanitizedRoomId]);
        if (Utils.IsErr(result)) return result;

        const rows : Array<any> = result.returnData.rows || [];

        const chatMsgs : ChatMsg[] = rows.map((row : Array<any>) : ChatMsg => ({

            userId: row[0],
            username: row[1],
            message: row[2],
            roomId: row[3],
            timestamp: row[4]

        }));

        return Utils.Ok(chatMsgs);

    }

    public static async SaveMessage(msg: ChatMsg) : Promise<Res> {

        const sanitizedRoom = this.SanitizeString(msg.roomId);
        const sanitizedUser = this.SanitizeString(msg.username);
        const sanitizedMess = this.SanitizeString(msg.message);

        if (IncomingValidator.ValidateMessageSize(sanitizedMess) === false) return Utils.Err("SAVE MESSAGE: Message was too big")
    
        const result = await(this.Query('INSERT INTO messages (roomId, userId, username, message, timestamp) VALUES (?, ?, ?, ?, ?)', [sanitizedRoom, msg.userId, sanitizedUser, sanitizedMess, msg.timestamp]));
        if (Utils.IsErr(result)) return result;

        return Utils.Ok();

    }

    public static async ClearMessages(roomId : string) : Promise<Res> {

        const sanitizedRoom = this.SanitizeString(roomId);

        const result = await(this.Query('DELETE FROM messages WHERE roomId = ?', [sanitizedRoom]))
        if (Utils.IsErr(result)) return result;

        return Utils.Ok();

    }

    public static async WaitUntilReady(): Promise<void> {

        return this.isReady;

    }

}

abstract class Room {

    protected clients = new Map<string, WebSocket>();
    protected roomId: string;
    protected emptyTimer: NodeJS.Timeout | null = null;
    protected static EMPTY_GRACE_MS = 30_000;

    protected constructor(roomID: string) {

        this.roomId = roomID;
        
    }

    protected IsClient(sessionId: string) : boolean {

        if (this.clients.get(sessionId)) {
        
            return true;
        
        } else {

            return false;

        }

    }

    protected AddClient(sessionId: string, ws: WebSocket): Res {

        if (this.IsClient(sessionId)) {
            return Utils.Err("ROOM ERR: Client already exists");
        }

        this.clients.set(sessionId, ws);

        this.ClearEmptyTimer();

        return Utils.Ok();
    }

    protected RemoveClient(sessionId : string): Res {

        const deleted = this.clients.delete(sessionId);
        if (deleted === false) return Utils.Err("ROOM ERR: Client doesnt exist anymore");

        if (this.clients.size === 0) {
        
            this.ScheduleDestroy();
        
        }

        return Utils.Ok();

    }

        protected ScheduleDestroy(): void {

            const graceMs = (this.constructor as typeof Room).EMPTY_GRACE_MS;

            this.emptyTimer = setTimeout(() => {

                if (this.clients.size === 0) {

                    this.Destroy();

                }

            }, graceMs);

        }

    protected ClearEmptyTimer() {
        
        if (this.emptyTimer) {

            clearTimeout(this.emptyTimer);
            this.emptyTimer = null;

        }

    }

    protected abstract Destroy(): void;

}

class SignalingRoom extends Room {

    private static signalingRooms = new Map<string, SignalingRoom>();
    protected static EMPTY_GRACE_MS = 60_000;

    private hostSessions = new Set<string>();
    private clientSessions = new Set<string>();

    protected constructor(roomId : string) {

        super(roomId);

    }

    public static async Init(roomID: string): Promise<Res> {

        let room = SignalingRoom.signalingRooms.get(roomID);

        if (!room) {

            room = new SignalingRoom(roomID);
            SignalingRoom.signalingRooms.set(roomID, room);

        }

        return Utils.Ok(room);

    }

    public IsHost(sessionId : string): boolean {

        return this.hostSessions.has(sessionId);

    }

    public IsRegisteredClient(sessionId : string): boolean {

        return this.clientSessions.has(sessionId);

    }

    public async MessageRTC(sessionId : string, sessionInfo: Session, verifiedRTCType : string, verifiedRTCObj : any) : Promise<Res> {

        if (!this.IsHost(sessionId) && !this.IsRegisteredClient(sessionId)) {
        
            return Utils.Err("RTC ERR: not a member of this room");
        
        }

        Messages.RTCMsg(this.roomId, Array.from(this.clients.values()), verifiedRTCType, verifiedRTCObj, sessionInfo.username, sessionInfo.userId, false);

        return Utils.Ok();

    }

    public async JoinRTC(sessionId : string, sessionInfo: Session, ws: WebSocket, wantsHost : boolean) : Promise<Res> {

        if (this.IsHost(sessionId) || this.IsRegisteredClient(sessionId)) return Utils.Err("RTC ERR: session already joined");

        if (wantsHost && this.hostSessions.size >= Config.MAX_HOSTS) return Utils.Err("RTC ERR: host slots full");
        if (!wantsHost && this.clientSessions.size >= Config.MAX_CLIENTS) return Utils.Err("RTC ERR: client slots full");

        const joinClient = super.AddClient(sessionId, ws); if (Utils.IsErr(joinClient) === true) return joinClient;

        if (wantsHost) { this.hostSessions.add(sessionId); } else { this.clientSessions.add(sessionId); }

        Messages.JoinLeaveMsg(this.roomId, Array.from(this.clients.values()), sessionInfo.username, sessionInfo.userId, true, false);

        return Utils.Ok();

    }

    public async LeaveRTC(sessionId: string, sessionInfo: Session) : Promise<Res> {

        const isHost = this.IsHost(sessionId);
        const isClient = this.IsRegisteredClient(sessionId);

        if (!isHost && !isClient) return Utils.Err("RTC ERR: session not in this room");

        const leaveClient = super.RemoveClient(sessionId); if (Utils.IsErr(leaveClient) === true) return leaveClient;

        if (isHost) { this.hostSessions.delete(sessionId); } else { this.clientSessions.delete(sessionId); }

        Messages.JoinLeaveMsg(this.roomId, Array.from(this.clients.values()), sessionInfo.username, sessionInfo.userId, false, false);

        return Utils.Ok();

    }

    protected Destroy(): void {

        this.ClearEmptyTimer();
        SignalingRoom.signalingRooms.delete(this.roomId);

    }

}

class ChatRoom extends Room {

    private static chatRooms = new Map<string, ChatRoom>();
    protected static EMPTY_GRACE_MS = 30_000;

    private chatList : ChatMsg[];

    protected constructor(roomId: string, chatMsgs : ChatMsg[]) {
        
        super(roomId);
        this.chatList = chatMsgs;

    }

    public static async Init(roomID: string): Promise<Res> {
        
        const getChat = await SQLServer.GetChats(roomID);
        if (Utils.IsErr(getChat) === true) return getChat;

        let room = ChatRoom.chatRooms.get(roomID);
        
        if (!room) {

            room = new ChatRoom(roomID, getChat.returnData as ChatMsg[]);
            ChatRoom.chatRooms.set(roomID, room);

        }

        return Utils.Ok(room);

    }

    public async JoinChat(sessionId: string, sessionInfo: Session, ws: WebSocket): Promise<Res> {

        const joinClient = super.AddClient(sessionId, ws); if (Utils.IsErr(joinClient) === true) return joinClient;

        Messages.JoinLeaveMsg(this.roomId, Array.from(this.clients.values()), sessionInfo.username, sessionInfo.userId, true, false)
        Messages.GiveMessagesMsg(this.roomId, this.chatList, ws, false);

        return Utils.Ok();

    }

    public async LeaveChat(sessionId: string, sessionInfo: Session): Promise<Res> {

        const leaveClient = super.RemoveClient(sessionId); if (Utils.IsErr(leaveClient) === true) return leaveClient;
        Messages.JoinLeaveMsg(this.roomId, Array.from(this.clients.values()), sessionInfo.username, sessionInfo.userId, false, false)

        return Utils.Ok();

    }

    public async MessageChat(sessionId : string, sessionInfo: Session, message : string) : Promise<Res> {

        if (this.IsClient(sessionId) === false) {

            return Utils.Err("CHAT ERR: not a member of this room");

        }

        const messageMsg = await Messages.MessageMsg(this.roomId, Array.from(this.clients.values()), message, sessionInfo.username, sessionInfo.userId, true);

        if (Utils.IsErr(messageMsg)) {

            return messageMsg;

        }

        this.chatList.push(messageMsg.returnData);

        return Utils.Ok();

    }

    protected Destroy(): void {

        this.ClearEmptyTimer();
        ChatRoom.chatRooms.delete(this.roomId);

    }

}