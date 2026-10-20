import {z} from 'zod';
import {Problem, VERSION, instructionsFor} from './node.mjs';

const handle = z.string().max(25).describe('A contact handle, like @pranav');
const time = z.string().max(40).describe('ISO 8601 time with a timezone offset, like 2026-10-10T14:00:00-05:00');
const slot = z.object({start: time, end: time});
const thread = z.string().max(40).describe('Thread id from check_inbox or an earlier tool result');

// On a software node nobody is asked: the approval happens as soon as the tool runs.
export function toolsFor(software = false) {
  const asks = software ? 'Takes effect immediately with this computer\'s software key, so only do it when your owner asked' : 'Asks your owner for Touch ID';
  return [
    {name: 'whoami', description: 'Your handle, key fingerprint, contacts (and whether each is verified), shared spaces, and approvals waiting for your owner.', input: z.object({}), run: node => node.whoami()},
    {name: 'check_inbox', description: 'Fetch new messages, availability requests and answers, plan proposals and confirmations, shared-space updates, and approvals waiting for your owner. Call it when an Agentchat alert starts you, or when your owner asks about plans, messages or friends.', input: z.object({}), run: node => node.checkInbox()},
    {name: 'get_thread', description: 'Full history of one conversation, including the free time common to everyone who answered and the status of each plan.', input: z.object({thread}), run: (node, a) => node.getThread(a)},
    {name: 'ask_availability', description: "Ask contacts whether they are free in a time window. Their agents check their own calendars and answer with free slots only. Pass your owner's free slots in my_slots so the common free time includes them.", input: z.object({to: z.array(handle).min(1).max(15), start: time, end: time, minutes: z.number().int().min(15).max(1440).describe('How long the plan needs, in minutes'), purpose: z.string().max(200).optional(), my_slots: z.array(slot).max(24).optional()}), run: (node, a) => node.askAvailability(a)},
    {name: 'reply_availability', description: "Answer an availability request with your owner's free time slots inside the requested window. Never include event titles, people, places or other calendar details. Use asking_owner if you need your owner to decide first.", input: z.object({thread, status: z.enum(['free', 'partly_free', 'busy', 'asking_owner']), slots: z.array(slot).max(24).optional(), note: z.string().max(200).optional()}), run: (node, a) => node.replyAvailability(a)},
    {name: 'send_message', description: 'Send an end-to-end encrypted message to contacts (to) or into an existing thread.', input: z.object({to: z.array(handle).max(15).optional(), thread: thread.optional(), text: z.string().min(1).max(2000)}), run: (node, a) => node.sendMessage(a)},
    {name: 'propose_plan', description: 'Propose a specific plan (title and time) to contacts or in a thread, usually after ask_availability found common free time.', input: z.object({to: z.array(handle).max(15).optional(), thread: thread.optional(), title: z.string().min(1).max(80), start: time, end: time, place: z.string().max(120).optional(), note: z.string().max(280).optional()}), run: (node, a) => node.proposePlan(a)},
    {name: 'respond_to_plan', description: `Accept, decline or counter a plan proposal. Accepting: ${asks}; only accept when your owner said yes.`, input: z.object({thread, plan: z.string().max(20).optional(), decision: z.enum(['accept', 'decline', 'counter']), counter_start: time.optional(), counter_end: time.optional(), note: z.string().max(280).optional()}), run: (node, a) => node.respondToPlan(a)},
    {name: 'read_space', description: 'Read a shared project space you are a member of. No approval is needed; every member can read it any time.', input: z.object({space: z.string().min(1).max(60).describe('Space name')}), run: (node, a) => node.readSpace(a)},
    {name: 'write_space', description: 'Add a note, task or link to a shared space. Every member can read it, so write only what all of them may see. Use replaces to update one of your earlier entries.', input: z.object({space: z.string().min(1).max(60), text: z.string().min(1).max(4000), title: z.string().max(80).optional(), kind: z.enum(['note', 'task', 'link']).optional(), replaces: z.string().max(40).optional()}), run: (node, a) => node.writeSpace(a)},
    {name: 'share_space', description: `Create a shared space or change who is in it. Members must be verified contacts. ${asks}; removing someone rotates the space key.`, input: z.object({space: z.string().min(1).max(60), add: z.array(handle).max(31).optional(), remove: z.array(handle).max(31).optional()}), run: (node, a) => node.shareSpace(a)},
    {name: 'add_contact', description: `Send a contact request to someone's handle. ${asks}, and their owner approves on their side.`, input: z.object({handle, note: z.string().max(140).optional()}), run: (node, a) => node.addContact(a)},
    {name: 'approve', description: `Approve or deny a contact request waiting for your owner. Approving: ${asks}, so only do it when they said yes. A contact's changed keys can't be accepted here: your owner compares safety numbers and runs agentchat verify in a terminal.`, input: z.object({id: z.string().max(40), decision: z.enum(['approve', 'deny']).optional()}), run: (node, a) => node.approve(a)},
  ];
}

export async function callTool(node, name, args) {
  const tools = toolsFor(node.software);
  const tool = tools.find(t => t.name === name) ?? (() => { throw new Problem(`Unknown tool “${name}”. Tools: ${tools.map(t => t.name).join(', ')}.`); })();
  const parsed = tool.input.safeParse(args ?? {});
  if (!parsed.success) throw new Problem(`Invalid arguments for ${name}: ${parsed.error.issues.map(i => `${i.path.join('.') || 'input'}: ${i.message}`).join('; ')}`);
  return tool.run(node, parsed.data);
}

export function mcpServer(node, McpServer) {
  const software = node.software;
  const server = new McpServer({name: 'agentchat', version: VERSION}, {capabilities: {tools: {}}, instructions: instructionsFor(software)});
  for (const tool of toolsFor(software)) {
    server.registerTool(tool.name, {description: tool.description, inputSchema: tool.input}, async args => {
      try { return {content: [{type: 'text', text: JSON.stringify(await tool.run(node, args), null, 2)}]}; } catch (error) {
        return {content: [{type: 'text', text: error instanceof Problem ? error.message : `Agentchat error: ${error.message}`}], isError: true};
      }
    });
  }
  return server;
}
