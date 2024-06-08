package main

import (
	"bytes"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"go/types"
	"golang.org/x/tools/go/packages"
	"log"
	"path"
)

func getStructs(src string) []types.Object {
	mode := packages.NeedName | packages.NeedFiles
	mode |= packages.NeedImports | packages.NeedDeps
	mode |= packages.NeedTypes | packages.NeedSyntax | packages.NeedTypesInfo
	dir, file := path.Split(src)
	_ = file
	cfg := &packages.Config{
		Mode: mode,
		Dir:  dir,
	}
	pkgs, err := packages.Load(cfg, "")
	if err != nil {
		log.Fatal(err)
	}
	if len(pkgs) != 1 {
		log.Fatal("pkg len not 1")
	}
	pkg := pkgs[0]
	info := pkg.TypesInfo

	var sts []types.Object
	for _, o := range info.Defs {
		if o == nil {
			continue
		}
		// TODO: Check file equality here.
		switch o.Type().Underlying().(type) {
		case *types.Struct:
			sts = append(sts, o)
		}
	}
	return sts
}

func genRcvr(name string) *ast.FieldList {
	return &ast.FieldList{
		List: []*ast.Field{{
			Names: []*ast.Ident{{Name: "o"}},
			Type:  &ast.StarExpr{X: &ast.Ident{Name: name}},
		}},
	}
}

func genFieldWrite(field *types.Var) ast.Stmt {
	name := field.Name()
	var call *ast.CallExpr
	switch field.Type().(*types.Basic).Kind() {
	case types.Uint64:
		call = &ast.CallExpr{
			Fun: &ast.SelectorExpr{
				X:   &ast.Ident{Name: "marshal"},
				Sel: &ast.Ident{Name: "WriteInt"},
			},
			Args: []ast.Expr{
				&ast.Ident{Name: "b"},
				&ast.SelectorExpr{
					X:   &ast.Ident{Name: "o"},
					Sel: &ast.Ident{Name: name},
				},
			},
		}
	default:
		log.Fatal("unsupported")
	}
	return &ast.AssignStmt{
		Lhs: []ast.Expr{&ast.Ident{Name: "b"}},
		Tok: token.ASSIGN,
		Rhs: []ast.Expr{call},
	}
}

func genEncode(o types.Object) *ast.FuncDecl {
	name := o.Name()
	st := o.Type().(*types.Named).Underlying().(*types.Struct)

	funcTy := &ast.FuncType{
		Results: &ast.FieldList{
			List: []*ast.Field{{
				Type: &ast.ArrayType{
					Elt: &ast.Ident{Name: "byte"},
				},
			}},
		},
	}
	callMake := &ast.CallExpr{
		Fun: &ast.Ident{Name: "make"},
		Args: []ast.Expr{
			&ast.ArrayType{
				Elt: &ast.Ident{Name: "byte"},
			},
			&ast.BasicLit{Kind: token.INT, Value: "0"},
		},
	}
	makeByteSl := &ast.DeclStmt{
		Decl: &ast.GenDecl{
			Tok: token.VAR,
			Specs: []ast.Spec{
				&ast.ValueSpec{
					Names:  []*ast.Ident{{Name: "b"}},
					Values: []ast.Expr{callMake},
				},
			},
		},
	}
	body := []ast.Stmt{makeByteSl}
	for i := 0; i < st.NumFields(); i++ {
		field := st.Field(i)
		body = append(body, genFieldWrite(field))
	}
	retStmt := &ast.ReturnStmt{
		Results: []ast.Expr{
			&ast.Ident{Name: "b"},
		},
	}
	body = append(body, retStmt)
	return &ast.FuncDecl{
		Recv: genRcvr(name),
		Name: &ast.Ident{Name: "encode"},
		Type: funcTy,
		Body: &ast.BlockStmt{List: body},
	}
}

func genFieldRead(field *types.Var) []ast.Stmt {
	name := field.Name()
	var call *ast.CallExpr
	switch field.Type().(*types.Basic).Kind() {
	case types.Uint64:
		call = &ast.CallExpr{
			Fun: &ast.SelectorExpr{
				X:   &ast.Ident{Name: "marshalutil"},
				Sel: &ast.Ident{Name: "SafeReadInt"},
			},
			Args: []ast.Expr{&ast.Ident{Name: "b"}},
		}
	default:
		log.Fatal("unsupported")
	}
	assign := &ast.AssignStmt{
		Lhs: []ast.Expr{
			&ast.Ident{Name: name},
			&ast.Ident{Name: "b"},
			&ast.Ident{Name: "err"},
		},
		Tok: token.DEFINE,
		Rhs: []ast.Expr{call},
	}
	err := &ast.IfStmt{
		Cond: &ast.Ident{Name: "err"},
		Body: &ast.BlockStmt{List: []ast.Stmt{
			&ast.ReturnStmt{
				Results: []ast.Expr{
					&ast.Ident{Name: "nil"},
					&ast.Ident{Name: "err"},
				},
			},
		}},
	}
	return []ast.Stmt{assign, err}
}

func genFieldAssign(field *types.Var) ast.Stmt {
	name := field.Name()
	return &ast.AssignStmt{
		Lhs: []ast.Expr{&ast.SelectorExpr{
			X:   &ast.Ident{Name: "o"},
			Sel: &ast.Ident{Name: name},
		}},
		Tok: token.ASSIGN,
		Rhs: []ast.Expr{&ast.Ident{Name: name}},
	}
}

func genDecode(o types.Object) *ast.FuncDecl {
	name := o.Name()
	st := o.Type().(*types.Named).Underlying().(*types.Struct)

	funcTy := &ast.FuncType{
		Params: &ast.FieldList{
			List: []*ast.Field{{
				Names: []*ast.Ident{{Name: "b0"}},
				Type: &ast.ArrayType{
					Elt: &ast.Ident{Name: "byte"},
				},
			}},
		},
		Results: &ast.FieldList{
			List: []*ast.Field{
				{Type: &ast.ArrayType{
					Elt: &ast.Ident{Name: "byte"},
				}},
				{Type: &ast.Ident{Name: "errorTy"}},
			},
		},
	}
	varDecl := &ast.DeclStmt{
		Decl: &ast.GenDecl{
			Tok: token.VAR,
			Specs: []ast.Spec{
				&ast.ValueSpec{
					Names:  []*ast.Ident{{Name: "b"}},
					Values: []ast.Expr{&ast.Ident{Name: "b0"}},
				},
			},
		},
	}
	ret := &ast.ReturnStmt{
		Results: []ast.Expr{
			&ast.Ident{Name: "b"},
			&ast.Ident{Name: "errNone"},
		},
	}
	body := []ast.Stmt{varDecl}
	for i := 0; i < st.NumFields(); i++ {
		field := st.Field(i)
		body = append(body, genFieldRead(field)...)
	}
	for i := 0; i < st.NumFields(); i++ {
		field := st.Field(i)
		body = append(body, genFieldAssign(field))
	}
	body = append(body, ret)
	return &ast.FuncDecl{
		Recv: genRcvr(name),
		Name: &ast.Ident{Name: "decode"},
		Type: funcTy,
		Body: &ast.BlockStmt{List: body},
	}
}

func genFileHeader() *ast.File {
	importDecl := &ast.GenDecl{
		Tok: token.IMPORT,
		Specs: []ast.Spec{
			&ast.ImportSpec{
				Path: &ast.BasicLit{
					Kind:  token.STRING,
					Value: "\"github.com/mit-pdos/pav/marshalutil\"",
				},
			},
			&ast.ImportSpec{
				Path: &ast.BasicLit{
					Kind:  token.STRING,
					Value: "\"github.com/tchajed/marshal\"",
				},
			},
		},
	}
	errTypeDecl := &ast.GenDecl{
		Tok: token.TYPE,
		Specs: []ast.Spec{
			&ast.TypeSpec{
				Name:   &ast.Ident{Name: "errorTy"},
				Assign: 1,
				Type:   &ast.Ident{Name: "bool"},
			},
		},
	}
	constErrDecl := &ast.GenDecl{
		Tok: token.CONST,
		Specs: []ast.Spec{
			&ast.ValueSpec{
				Names:  []*ast.Ident{{Name: "errNone"}},
				Type:   &ast.Ident{Name: "errorTy"},
				Values: []ast.Expr{&ast.Ident{Name: "false"}},
			},
			&ast.ValueSpec{
				Names:  []*ast.Ident{{Name: "errSome"}},
				Type:   &ast.Ident{Name: "errorTy"},
				Values: []ast.Expr{&ast.Ident{Name: "true"}},
			},
		},
	}
	// Hacky: pkg comment fix. Pkg starts after pkg comment.
	commentPos := token.Pos(1)
	comment := &ast.Comment{
		Slash: commentPos,
		Text:  "// Auto-generated from github.com/mit-pdos/pav/rpc.",
	}
	file := &ast.File{
		Doc:     &ast.CommentGroup{List: []*ast.Comment{comment}},
		Package: commentPos + 1,
		Name:    &ast.Ident{Name: "rpc"},
		Decls: []ast.Decl{
			importDecl,
			errTypeDecl,
			constErrDecl,
		},
	}
	return file
}

func printGo(n any) []byte {
	fset := token.NewFileSet()
	// Hacky: pkg comment fix. Range big enough to fit both specified pos's.
	fset.AddFile("out.go", 1, 1)
	buf := new(bytes.Buffer)
	err := format.Node(buf, fset, n)
	if err != nil {
		log.Fatal(err)
	}
	return buf.Bytes()
}

// printAst when developing. See AST of golden files.
func printAst(src []byte) []byte {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "", src, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		log.Fatal(err)
	}
	res := new(bytes.Buffer)
	ast.Fprint(res, fset, f, ast.NotNilFilter)
	return res.Bytes()
}

func compile(src string) []byte {
	sts := getStructs(src)
	f := genFileHeader()
	for _, st := range sts {
		enc := genEncode(st)
		dec := genDecode(st)
		f.Decls = append(f.Decls, enc, dec)
	}
	return printGo(f)
}
