Scope of security AgentXDR gives us


1. Code & Context
    1. GitHub
            1. Monitor the code changes every push 
                    a. overprivileged Tool Access
                    b. Authentication and Authorisations
                    c. Dependencies monitering 
                    d. Instructions 
                    e. Tools and Context
        (privileged pulls vs flagging weakening PR'S)

            2. Context
                a. System Instruction's
                b. RAG (semantic store) --> RABC
                c. User Input
                d. Memory 
                e. Tool output's and description's context
                f. cryptographically hash/pin tool schemas validation. 
                g. Shadow mcp discovers
    2. Pre-Deployment Red Teaming & Adversarial :
            a. Pyrit 
             b. Automated Red team inputs and output monitoring 

                
2. External Tools and Dependencies test 
3. Gaurdrails 
    a. Gaurdrails on the user inputs 
    b. Actions 
            aa. Automatic actions 
            ab. Privileged Actions
            ac. Blocked or restricted Actions
    c. Guardrail's on the stored data
    d. Restrictions on the Loops
    e. Output Gaurdrails 
            aa. Harmfull Gaurdrali
            ab. Semantic Filter 
            ac. Deterministic imp data masker's (prompt, keys, PII)
         

4. Moniterings Whhile running (Observability)
    1. Loggers (changes to be logged properly)
        a. User input
        b. Memory 
        c. RAG sources 
        d. Tool Calls
        e. Agent Communication

    2. Drift calculations 
        a. calculating Drift from the intended path 
                aa. no of tool calls or no of turns 
                ab. Responses drift calculations (embeddings or semantic )
                ac. Graph for the actions it took to find anomalies 
      3. Unexpected Code Executions 
                aa. Code sanitisations 
                ab. Sandbox executions 
                ac. Approval escalations 
5. Respond for situations 
    1. Kill Switches 
            a. for modules 
            b. for entière flow

    2. Blast Radius and Quarantines 
    3. Store and Roll Backs 


6. Monitoring the roles and permissions 
    a. roles and permissions should be versioned 
    b. need approval and maintain 
    c. Higher Privileges should be monitered and guarded
