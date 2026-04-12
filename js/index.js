export class Room {
  constructor() {
    this.socket = new Map();
    this.socketStore = {offer: null, clientICE: []};
    this.firstClient = true;
  }

  async fetch(request) {
    
    const [client, server] = Object.values(new WebSocketPair());

    const booleanCheck = this.firstClient == true;

    const origin = request.headers.get("Origin");
    const headerCheck = origin === null || origin === "file://";

    //two host check and client empty check
    if ((headerCheck == true && booleanCheck == false)) {

        return new Response("Host already connected in this room", { status: 403 })
    
    } else if ((booleanCheck == true && headerCheck == false)) {

        return new Response("Cannot connect to empty room as client", { status: 403 })
    
    }

    const isHost = headerCheck && booleanCheck;

    this.socket.set(isHost, server);
    server.accept();

    if (this.firstClient == true) {
      
        this.firstClient = false;
    
    } else {
       
        const target = this.socket.get(false);
       
        if (this.socketStore.offer !== null) {
            target.send(JSON.stringify({ type: "offer", actualData: this.socketStore.offer }))
        }
       
        if (this.socketStore.clientICE.length > 0) {
            target.send(JSON.stringify({ type: "ICE", actualData: this.socketStore.clientICE }))
        }
    
    }

    server.addEventListener("message", msg => {

        let hostOpp = !isHost;
        const data = JSON.parse(msg.data);
        
        if (data.type && data.actualData) {
            
            const target = this.socket.get(hostOpp)
            
            if (isHost == true && data.type == "ICE") {
            
                this.socketStore.clientICE.push(data.actualData)
            
            } else if (isHost == true && data.type == "offer") {
            
                this.socketStore.offer = data.actualData;
            
            } else if (target) {
            
                target.send(msg.data);
            
            }
         
        }
    
    });

    server.addEventListener("close", () => {

        this.socket.delete(isHost);
        
        if (isHost == true) {
            
            this.firstClient = true
            this.socketStore = { offer: null, clientICE: [] }
            
            const client = this.socket.get(false)
            
            if (client) {
                
                client.close()
                this.socket.delete(false)
            
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

    if (roomId !== null) {

        const roomClass = env.ROOM.idFromName(roomId);
        const stub = env.ROOM.get(roomClass);

        return stub.fetch(request);

    } else {
        
        return new Response("missing name", { status: 400 });

    }

  }

};