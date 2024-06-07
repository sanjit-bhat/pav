package rpc

import (
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"go/types"
	"log"
	"os"
	"path"
)

type context struct {
	fpath string
	fset  *token.FileSet
	info  *types.Info
}

func (ctx *context) typeCheck() {
	ctx.fset = token.NewFileSet()
	file, err := parser.ParseFile(ctx.fset, ctx.fpath, nil, parser.SkipObjectResolution)
	if err != nil {
		log.Fatal(err)
	}
	files := []*ast.File{file}
	conf := types.Config{}
	ctx.info = &types.Info{
		Defs: make(map[*ast.Ident]types.Object),
	}
	_, err = conf.Check(path.Base(ctx.fpath), ctx.fset, files, ctx.info)
	if err != nil {
		log.Fatal(err)
	}
}

func (ctx *context) getStructs() []types.Object {
	var sts []types.Object
	for _, o := range ctx.info.Defs {
		if o == nil {
			continue
		}
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

func genWriteInt(name string) *ast.AssignStmt {
	rhs := []ast.Expr{
		&ast.CallExpr{
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
		},
	}
	return &ast.AssignStmt{
		Lhs: []ast.Expr{&ast.Ident{Name: "b"}},
		Tok: token.ASSIGN,
		Rhs: rhs,
	}
}

func genEncode(o types.Object) *ast.FuncDecl {
	name := o.Name()
	st := o.Type().(*types.Named).Underlying().(*types.Struct)

	funcTy := &ast.FuncType{
		Params: &ast.FieldList{},
		Results: &ast.FieldList{
			List: []*ast.Field{{
				Type: &ast.ArrayType{
					Elt: &ast.Ident{Name: "byte"},
				},
			}},
		},
	}
	makeByteSl := &ast.DeclStmt{
		Decl: &ast.GenDecl{
			Tok: token.VAR,
			Specs: []ast.Spec{
				&ast.ValueSpec{
					Names: []*ast.Ident{{Name: "b"}},
					Values: []ast.Expr{
						&ast.CallExpr{
							Fun: &ast.Ident{Name: "make"},
							Args: []ast.Expr{
								&ast.ArrayType{
									Elt: &ast.Ident{Name: "byte"},
								},
								&ast.BasicLit{Kind: token.INT, Value: "0"},
							},
						},
					},
				},
			},
		},
	}
	body := &ast.BlockStmt{
		List: []ast.Stmt{
			makeByteSl,
		},
	}
	for i := 0; i < st.NumFields(); i++ {
		field := st.Field(i)
		fieldName := field.Name()
		switch field.Type().(*types.Basic).Kind() {
		case types.Uint64:
			body.List = append(body.List, genWriteInt(fieldName))
		default:
			panic("unsupported")
		}
	}
	retStmt := &ast.ReturnStmt{
		Results: []ast.Expr{
			&ast.Ident{Name: "b"},
		},
	}
	body.List = append(body.List, retStmt)
	return &ast.FuncDecl{
		Recv: genRcvr(name),
		Name: &ast.Ident{Name: "encode"},
		Type: funcTy,
		Body: body,
	}
}

func printAst(fpath string) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, fpath, nil, parser.SkipObjectResolution)
	if err != nil {
		panic(err)
	}
	ast.Print(fset, f.Decls[3])
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
				Name: &ast.Ident{Name: "errorTy"},
				Type: &ast.Ident{Name: "bool"},
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

	file := &ast.File{
		Name: &ast.Ident{Name: "main"},
		Decls: []ast.Decl{
			importDecl,
			errTypeDecl,
			constErrDecl,
		},
	}

	return file
}

func printNode(n any) {
	err := format.Node(os.Stdout, token.NewFileSet(), n)
	if err != nil {
		log.Fatal(err)
	}
}

func driver(fpath string) {
	printAst("out.gold.go")
	_ = fpath

	ctx := &context{fpath: fpath}
	ctx.typeCheck()
	f := genFileHeader()
	sts := ctx.getStructs()
	for _, st := range sts {
		enc := genEncode(st)
		f.Decls = append(f.Decls, enc)
	}
	printNode(f)
}
