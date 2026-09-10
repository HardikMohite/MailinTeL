import React, { useState, useRef, useEffect } from 'react';
import {
  Sparkles,
  Send,
  X,
  Bot,
  User,
  RefreshCw,
  Database,
} from 'lucide-react';
import {
  investigateCaseWithAI,
  AIInvestigateResponse,
} from '../../services/api';

interface Message {
  role: 'user' | 'assistant';
  content: string;
  sources?: Record<string, number>;
  timestamp?: string;
}

interface AIAssistantDrawerProps {
  emailId: string;
  emailSubject?: string;
  isOpen: boolean;
  onClose: () => void;
}

const SUGGESTED_QUESTIONS = [
  'Why is this email considered high risk?',
  'Which emails are related to this message?',
  'What infrastructure overlaps were found?',
  'Explain the relay hop path.',
  'Summarize this case.',
];

export const AIAssistantDrawer: React.FC<AIAssistantDrawerProps> = ({
  emailId,
  emailSubject,
  isOpen,
  onClose,
}) => {
  const [messages, setMessages] = useState<Message[]>([
    {
      role: 'assistant',
      content:
        'I am your MailIntel Forensic Investigation Assistant. I am grounded strictly in this case\'s verified headers, cryptographic authentication, observable IOCs, and pgvector similarities. Ask me anything about this case.',
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    },
  ]);
  const [inputValue, setInputValue] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const messagesEndRef = useRef<HTMLDivElement | null>(null);

  // Auto-scroll to bottom on message update
  useEffect(() => {
    if (isOpen) {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, isOpen]);

  // Reset when email changes
  useEffect(() => {
    setMessages([
      {
        role: 'assistant',
        content:
          'I am your MailIntel Forensic Investigation Assistant. I am grounded strictly in this case\'s verified headers, cryptographic authentication, observable IOCs, and pgvector similarities. Ask me anything about this case.',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      },
    ]);
  }, [emailId]);

  if (!isOpen) return null;

  const handleSend = async (questionText?: string) => {
    const q = (questionText || inputValue).trim();
    if (!q || loading || !emailId) return;

    const userMsg: Message = {
      role: 'user',
      content: q,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputValue('');
    setLoading(true);

    try {
      const history = messages
        .filter((m) => m.content)
        .map((m) => ({ role: m.role, content: m.content }));

      const res: AIInvestigateResponse = await investigateCaseWithAI(emailId, q, history);

      const assistantMsg: Message = {
        role: 'assistant',
        content: res.answer,
        sources: res.grounded_sources,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };

      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err: any) {
      console.error('Investigation assistant error:', err);
      const errorMsg: Message = {
        role: 'assistant',
        content:
          err?.response?.data?.detail ||
          'Failed to retrieve answer from case evidence. Please check network connectivity.',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-slate-950/60 backdrop-blur-sm transition-opacity"
        onClick={onClose}
      />

      {/* Drawer Container */}
      <div className="relative w-full max-w-lg bg-slate-900 border-l border-slate-800 shadow-2xl flex flex-col h-full z-10">
        {/* Header */}
        <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/50">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
              <Sparkles className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-semibold text-slate-100">
                  Case Investigation Assistant
                </h3>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-300">
                  RAG Grounded
                </span>
              </div>
              <p className="text-xs text-slate-400 truncate max-w-[280px]">
                {emailSubject || `Case ${emailId.slice(0, 8)}`}
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Messages Thread */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {messages.map((msg, idx) => (
            <div
              key={idx}
              className={`flex gap-3 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
            >
              {msg.role === 'assistant' && (
                <div className="w-7 h-7 rounded-lg bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400 shrink-0 mt-0.5">
                  <Bot className="w-4 h-4" />
                </div>
              )}

              <div
                className={`max-w-[85%] rounded-xl p-3.5 text-xs leading-relaxed ${
                  msg.role === 'user'
                    ? 'bg-cyan-600 text-white rounded-br-none shadow-md'
                    : 'bg-slate-800/80 border border-slate-700/60 text-slate-200 rounded-bl-none'
                }`}
              >
                <div className="whitespace-pre-wrap">{msg.content}</div>

                {msg.sources && Object.keys(msg.sources).length > 0 && (
                  <div className="mt-2.5 pt-2 border-t border-slate-700/60 flex flex-wrap gap-2 text-[10px] text-slate-400 font-mono">
                    <span className="flex items-center gap-1">
                      <Database className="w-3 h-3 text-cyan-400" />
                      Grounded: {msg.sources.findings_count ?? 0} findings,{' '}
                      {msg.sources.similar_emails_count ?? 0} similar emails
                    </span>
                  </div>
                )}

                <div
                  className={`text-[9px] font-mono mt-1 ${
                    msg.role === 'user' ? 'text-cyan-200/80 text-right' : 'text-slate-500'
                  }`}
                >
                  {msg.timestamp}
                </div>
              </div>

              {msg.role === 'user' && (
                <div className="w-7 h-7 rounded-lg bg-cyan-600/20 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shrink-0 mt-0.5">
                  <User className="w-4 h-4" />
                </div>
              )}
            </div>
          ))}

          {loading && (
            <div className="flex gap-3 justify-start">
              <div className="w-7 h-7 rounded-lg bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400 shrink-0">
                <Bot className="w-4 h-4" />
              </div>
              <div className="p-3.5 rounded-xl bg-slate-800/80 border border-slate-700/60 text-slate-400 text-xs flex items-center gap-2">
                <RefreshCw className="w-3.5 h-3.5 animate-spin text-cyan-400" />
                <span>Querying case evidence via Groq...</span>
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Quick Question Chips */}
        <div className="p-3 border-t border-slate-800/80 bg-slate-950/30">
          <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider mb-2">
            Suggested Case Queries
          </div>
          <div className="flex flex-wrap gap-1.5">
            {SUGGESTED_QUESTIONS.map((q, idx) => (
              <button
                key={idx}
                disabled={loading}
                onClick={() => handleSend(q)}
                className="text-[11px] px-2.5 py-1 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700/60 transition-colors disabled:opacity-50 text-left"
              >
                {q}
              </button>
            ))}
          </div>
        </div>

        {/* Input Bar */}
        <div className="p-3 border-t border-slate-800 bg-slate-950 flex items-center gap-2">
          <input
            type="text"
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            onKeyDown={handleKeyDown}
            disabled={loading}
            placeholder="Ask about this case (e.g., Explain the relay path)..."
            className="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-3.5 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors disabled:opacity-50"
          />
          <button
            onClick={() => handleSend()}
            disabled={loading || !inputValue.trim()}
            className="p-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-800 text-white disabled:text-slate-600 transition-colors shrink-0"
          >
            <Send className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
};
